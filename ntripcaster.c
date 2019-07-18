#include <time.h>
#include "logh/log.h"
#include "wsocket/wsocket.h"
#include "queue.h"

#ifdef _WIN32
# include "evwrap.h"
#else
# include <ev.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stddef.h>
#include <signal.h>

enum ntrip_agent_type {
    NTRIP_PENDING_AGENT = 0,
    NTRIP_SOURCE_AGENT,
    NTRIP_CLIENT_AGENT,
    NTRIP_AGENT_SENTRY,
};

struct ntrip_caster;

struct ntrip_agent {
    ev_io io;
    wsocket socket;
    int  type;                  // agent type: ntrip_agent_type
    char mountpoint[64];        // mountpoint requested by agent
    char peeraddr[NI_MAXHOST];  // agent ip address
    char user_agent[64];        // agent ntrip user agent string
    time_t login_time;          // agent login time
    ev_tstamp last_activity;    // agent last IO time
    unsigned char pending_recv[1024];// pending agent socket recv buffer
    size_t pending_idx;              // pending agent socket recv buffer index

    size_t in_bytes;    // in bound bytes
    size_t in_bps;      // in bound bps
    size_t out_bytes;   // out bound bytes
    size_t out_bps;     // out bound bps

    struct ntrip_caster* caster; // caster associate with agent(not change during whole agent lifetime)
    TAILQ_ENTRY(ntrip_agent) entries;  // agent list
};

// for authorization
struct ntrip_token {
    char token[64];         // token
    char mnt[64];      // associate mountpoint
    TAILQ_ENTRY(ntrip_token) entries;   // token list
};

struct ntrip_caster_config {
    size_t MAX_PENDING_CNT; // pending agent count limit, 0 means no limit
    size_t MAX_CLIENT_CNT;  // client agent count limit, 0 means no limit
    size_t MAX_SOURCE_CNT;  // source agent count limit, 0 meas not limit
    // token & other config
    TAILQ_HEAD(, ntrip_token) client_token_head;  // client token list
    TAILQ_HEAD(, ntrip_token) source_token_head;  // source token list
    char   bind_addr[64];   // caster bind address, "" means NULL
    char   bind_serv[16];   // caster bind port service
};

struct ntrip_caster {
    ev_io io;
    ev_timer timer; // timer for check agent alive
    wsocket socket;
    TAILQ_HEAD(, ntrip_agent) agents_head[NTRIP_AGENT_SENTRY]; // agent list for PENDING/CLIENT/SOURCE
    size_t agents_cnt[NTRIP_AGENT_SENTRY];   // agents count for PENDING/CLIENT/SOURCE
    struct ntrip_caster_config config;  // config
};


#define DEFAULT_MAX_PENDING_AGENT   5
#define DEFAULT_MAX_CLIENT_AGENT    5
#define DEFAULT_MAX_SOURCE_AGENT    3


#define NTRIP_RESPONSE_OK           "ICY 200 OK\r\n"
#define NTRIP_RESPONSE_UNAUTHORIZED "HTTP/1.0 401 Unauthorized\r\n"
#define NTRIP_RESPONSE_FORBIDDEN    "HTTP/1.0 403 Forbidden\r\n"
#define NTRIP_RESPONSE_ERROR_PASSED "ERROR - Bad Password\r\n"
#define NTRIP_RESPONSE_ERROR_MOUNTP "ERROR - Bad Mountpoint\r\n"

static wsocket listen_on(const char *addr, const char* service)
{
    wsocket sock = INVALID_WSOCKET;

    struct addrinfo hints = {0};
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int rv = 0;
    struct addrinfo *ai = NULL;
    if ((rv = getaddrinfo(addr, service, &hints, &ai)) != 0) {
        LOG_ERROR("getaddrinfo() error, %s", gai_strerror(rv));
        return INVALID_WSOCKET;
    }
    for (const struct addrinfo *p = ai; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (wsocket_set_nonblocking(sock) == WSOCKET_ERROR) {
            LOG_ERROR("set nonblocking error, %s", wsocket_strerror(wsocket_errno));
            wsocket_close(sock);
            return INVALID_WSOCKET;
        }
        if (sock == INVALID_WSOCKET) {
            continue;
        }
        // enable addr resuse
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
        if (bind(sock, p->ai_addr, p->ai_addrlen) == WSOCKET_ERROR) {
            // bind error
            wsocket_close(sock);
            sock = INVALID_WSOCKET;
            continue;
        }
        // Got it!
        break;
    }

    if (sock == INVALID_WSOCKET) {
        LOG_ERROR("socket() or bind() error, %s", wsocket_strerror(wsocket_errno));
        freeaddrinfo(ai);
        ai = NULL;
        return INVALID_WSOCKET;
    }

    freeaddrinfo(ai);
    ai = NULL;

    if (listen(sock, 2) == WSOCKET_ERROR) {
        LOG_ERROR("listen() error, %s", wsocket_strerror(wsocket_errno));
        wsocket_close(sock);
        return INVALID_WSOCKET;
    }

    return sock;
}


static void close_agent(struct ntrip_agent *agent)
{
    LOG_INFO("close agent(%d) from %s", agent->socket, agent->peeraddr);
    TAILQ_REMOVE(&agent->caster->agents_head[agent->type], agent, entries);
    agent->caster->agents_cnt[agent->type] -= 1;
    wsocket_close(agent->socket);
    free(agent);
}

static void delay_close_once_cb(int revents, void* arg)
{
    if (revents & EV_TIMER) {
        struct ntrip_agent *agent = arg;
        LOG_INFO("now will close agent(%d) after delay", agent->socket);
        close_agent(agent);
    }
}


// check if caster has  the mountpoint source
static int caster_has_mountpoint(const struct ntrip_caster *caster, const char* mnt)
{
    // invalid mnt
    if (mnt[0] == '\0' || strcmp(mnt, "/") == 0) {
        return 0;
    }
    struct ntrip_agent *server;
    TAILQ_FOREACH(server, &caster->agents_head[NTRIP_SOURCE_AGENT], entries) {
        if (strcasecmp(server->mountpoint, mnt) == 0) {
            return 1;
        }
    }
    return 0;
}

static const char* caster_gen_sourcetable(const struct ntrip_caster *caster)
{
    // only generate once in few seconds
    // max source table chars sizeof(_srctbbuf) - 1
    static ev_tstamp _srctbupdt = 0;
    static char _srctbbuf[10240];
    // return old generate if just a little later
    ev_tstamp now = ev_time();
    if (now - _srctbupdt <= 3.0) {
        return _srctbbuf;
    }
    _srctbupdt = now;
    _srctbbuf[0] = '\0';
    char str[256];
    int idx = 0;
    struct ntrip_agent *agent;
    TAILQ_FOREACH(agent, &caster->agents_head[NTRIP_SOURCE_AGENT], entries) {
        str[0] = '\0';
        // format one str
        int rv = snprintf(str, sizeof(str),
                          "STR;%s;%s;RTCM3X;1005(10),1074-1084-1124(1);2;GNSS;NET;CHN;0.00;0.00;1;1;None;None;B;N;%zu;\r\n",
                          agent->mountpoint, agent->mountpoint, agent->in_bps);
        if (rv <= 0) {
            break;
        }
        rv = snprintf(_srctbbuf + idx, sizeof(_srctbbuf) - idx, "%s", str);
        if (rv <= 0) {
            break;
        }
        idx += rv;
        if (idx >= sizeof(_srctbbuf) - 20) {
            break;
        }
    }
    snprintf(_srctbbuf + idx, sizeof(_srctbbuf) - idx, "ENDSOURCETABLE\r\n");
    return _srctbbuf;
}

static int caster_match_client_token(const struct ntrip_caster *caster, const char* token, const char* mnt)
{
    struct ntrip_token *key;
    TAILQ_FOREACH(key, &caster->config.client_token_head, entries) {
        if (strcmp(token, key->token) == 0) {
            // TODO: wildcard matching
            if (strcasecmp(key->mnt, mnt) == 0 || strcmp(key->mnt, "*") == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static int caster_match_source_token(const struct ntrip_caster *caster, const char* token, const char* mnt)
{
    struct ntrip_token *key;
    TAILQ_FOREACH(key, &caster->config.source_token_head, entries) {
        if (strcmp(token, key->token) == 0) {
            // TODO: wildcard matching
            if (strcasecmp(key->mnt, mnt) == 0 || strcmp(key->mnt, "*") == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static void agent_read_cb(EV_P_ ev_io *w, int revents)
{
    struct ntrip_agent *agent = (struct ntrip_agent *)w;

    if (agent->type == NTRIP_PENDING_AGENT) {
        // read and check what type agent
        int n = recv(agent->socket,
                     agent->pending_recv + agent->pending_idx,
                     sizeof(agent->pending_recv) - agent->pending_idx - 1,
                     0);

        if (n == WSOCKET_ERROR && wsocket_errno != WSOCKET_EWOULDBLOCK) {
            LOG_ERROR("agent(%d) recv error, %s", agent->socket, wsocket_strerror(wsocket_errno));
            ev_io_stop(EV_A_ &agent->io);
            close_agent(agent);
            return;
        }
        if (n == 0) {
            LOG_INFO("agent(%d) connection close", agent->socket);
            ev_io_stop(EV_A_ &agent->io);
            close_agent(agent);
            return;
        }
        if (n < 0) { // maybe -1 since WSOCKET_EWOULDBLOCK
            return;
        }
        agent->last_activity = ev_now(EV_A);
        agent->pending_idx =+ n;
        // check pending buffer overflow
        if (agent->pending_idx >= sizeof(agent->pending_recv) - 1) {
            LOG_ERROR("agent(%d) request buffer overflow", agent->socket);
            ev_io_stop(EV_A_ &agent->io);
            close_agent(agent);
            return;
        }
        agent->pending_recv[agent->pending_idx] = '\0';
        // test GET (ntrip client) or SOURCE (ntrip server)
        do {
            char* p = strstr(agent->pending_recv, "GET");
            if (p) {
                // ntrip client
                char *q, *ag;
                if (!(q = strstr(p, "\r\n")) || !(ag = strstr(q, "User-Agent:")) || !strstr(ag, "\r\n")) {
                    break;
                }
                ag += strlen("User-Agent:");
                // fill user agent
                sscanf(ag, "%63[^\n]", agent->user_agent);
                // test protocol
                char url[64], proto[64];
                url[0] = '\0';
                proto[0] = '\0';
                if (sscanf(p, "GET %63s %63s", url, proto) < 2 || strncmp(proto, "HTTP/1", strlen("HTTP/1")) != 0) {
                    LOG_ERROR("invalid ntrip proto=%s", proto);
                    break;
                }
                snprintf(agent->mountpoint, sizeof(agent->mountpoint), "%s", url[0] == '/' ? url + 1 : url);
                // check if mountpoint exist, if not , send source table
                if (!caster_has_mountpoint(agent->caster, agent->mountpoint)) {
                    // send source table
                    LOG_DEBUG("send source table to agent(%d) from %s",
                              agent->socket, agent->peeraddr);
                    const char *srctb = caster_gen_sourcetable(agent->caster);
                    int srctblen = strlen(srctb);
                    char buf[256];
                    buf[0] = '\0';
                    time_t now = time(NULL);
                    // NOTE: DO NOT use time functions in LOG_XXX macros
                    char* timestr = strdup(asctime(gmtime(&now)));
                    snprintf(buf, sizeof(buf),
                             "SOURCETABLE 200 OK\r\n"
                             "Server: Ntripcaster 1.0\r\n"
                             "Date: %.24s UTC\r\n"
                             "Connection: close\r\n"
                             "Content-Type: text/plain\r\n"
                             "Content-Length: %d\r\n\r\n",
                             timestr, srctblen);
                    free(timestr);
                    if (send(agent->socket, buf, strlen(buf), 0) > 0) {
                        send(agent->socket, srctb, srctblen, 0);
                    }
                    // delay close it to ensure send complete
                    ev_io_stop(EV_A_ &agent->io);
                    ev_once(EV_A_ -1, EV_READ, 2.0, delay_close_once_cb, agent);
                    return;
                }
                // check authentication
                int auth = 0; // if authorization success
                if ((p = strstr(agent->pending_recv, "Authorization:"))) {
                    char method[32];
                    char token[64];
                    method[0] = '\0';
                    token[0] = '\0';
                    if (sscanf(p, "Authorization: %31s %63s", method, token) == 2) {
                        if (strcmp(method, "Basic") == 0) {
                            // match token
                            if (caster_match_client_token(agent->caster, token, agent->mountpoint)) {
                                auth = 1;
                            }
                        }
                    }
                }
                if (!auth) { // auth failed
                    LOG_INFO("agent(%d) client authorization failed.", agent->socket);
                    send(agent->socket, NTRIP_RESPONSE_UNAUTHORIZED,
                         strlen(NTRIP_RESPONSE_UNAUTHORIZED), 0);
                    break;
                }
                // check if client agents max count
                if (agent->caster->config.MAX_CLIENT_CNT > 0 &&
                    agent->caster->config.MAX_CLIENT_CNT <= agent->caster->agents_cnt[NTRIP_CLIENT_AGENT]) {
                    LOG_WARN("too many client agents, now=%zu, MAX=%zu",
                             agent->caster->agents_cnt[NTRIP_CLIENT_AGENT],
                             agent->caster->config.MAX_CLIENT_CNT);
                    // send error message
                    send(agent->socket, NTRIP_RESPONSE_FORBIDDEN, strlen(NTRIP_RESPONSE_FORBIDDEN), 0);
                    LOG_INFO("kickoff pending agent(%d) from %s", agent->socket, agent->peeraddr);
                    ev_io_stop(EV_A_ &agent->io);
                    close_agent(agent);
                    return;
                }
                // send response
                send(agent->socket, NTRIP_RESPONSE_OK, strlen(NTRIP_RESPONSE_OK), 0);
                // move to clients list from pending
                agent->pending_idx = 0;
                TAILQ_REMOVE(&agent->caster->agents_head[agent->type], agent, entries);
                agent->caster->agents_cnt[agent->type] -= 1;
                agent->type = NTRIP_CLIENT_AGENT;
                TAILQ_INSERT_TAIL(&agent->caster->agents_head[agent->type], agent, entries);
                agent->caster->agents_cnt[agent->type] += 1;
                LOG_INFO("move agent(%d) into client agents", agent->socket);
                return;
            }
            p = strstr(agent->pending_recv, "SOURCE");
            if (p) {
                // ntrip server
                char *q, *ag;
                if (!(q = strstr(p, "\r\n")) || !(ag = strstr(q, "Source-Agent:")) || !strstr(ag, "\r\n")) {
                    break;
                }
                ag += strlen("Source-Agent:");
                // fill user agent
                sscanf(ag, "%63[^\n]", agent->user_agent);
                // get passwd and url
                char url[64], passwd[64];
                url[0] = '\0';
                passwd[0] = '\0';
                if (sscanf(p, "SOURCE %63s %63s", passwd, url) < 2) {
                    break;
                }
                snprintf(agent->mountpoint, sizeof(agent->mountpoint), "%s", url[0] == '/' ? url + 1 : url);
                // check if mountpoint
                if (agent->mountpoint[0] == '\0' || strcmp(agent->mountpoint, "/") == 0) {
                    LOG_WARN("agent(%d) source invalid mountpoint '%s'", agent->socket, agent->mountpoint);
                    send(agent->socket, NTRIP_RESPONSE_ERROR_MOUNTP, strlen(NTRIP_RESPONSE_ERROR_MOUNTP), 0);
                    break;
                }
                // check authentication
                if (!caster_match_source_token(agent->caster, passwd, agent->mountpoint)) {
                    LOG_WARN("agent(%d) source authorization failed.", agent->socket);
                    send(agent->socket, NTRIP_RESPONSE_ERROR_PASSED,
                         strlen(NTRIP_RESPONSE_ERROR_PASSED), 0);
                    break;
                }
                // check if mountpoint source already exists
                // if so, then reject new agent
                if (caster_has_mountpoint(agent->caster, agent->mountpoint)) {
                    // reject new agent
                    LOG_WARN("agent(%d) attempt source mountpoint(%s) which already has source agent",
                             agent->socket, agent->mountpoint);
                    send(agent->socket, NTRIP_RESPONSE_ERROR_MOUNTP, strlen(NTRIP_RESPONSE_ERROR_MOUNTP), 0);
                    break;
                }
                // check if source agents count max
                if (agent->caster->config.MAX_SOURCE_CNT > 0 &&
                    agent->caster->config.MAX_SOURCE_CNT <= agent->caster->agents_cnt[NTRIP_SOURCE_AGENT]) {
                    LOG_WARN("too many source agents, now=%zu, MAX=%zu",
                             agent->caster->agents_cnt[NTRIP_SOURCE_AGENT],
                             agent->caster->config.MAX_SOURCE_CNT);
                    // send error message
                    send(agent->socket, NTRIP_RESPONSE_ERROR_MOUNTP, strlen(NTRIP_RESPONSE_ERROR_MOUNTP), 0);
                    LOG_INFO("kickoff pending agent(%d) from %s", agent->socket, agent->peeraddr);
                    ev_io_stop(EV_A_ &agent->io);
                    close_agent(agent);
                    return;
                }
                // send response
                send(agent->socket, NTRIP_RESPONSE_OK, strlen(NTRIP_RESPONSE_OK), 0);
                // move to sources list from pending
                agent->pending_idx = 0;
                TAILQ_REMOVE(&agent->caster->agents_head[agent->type], agent, entries);
                agent->caster->agents_cnt[agent->type] -= 1;
                agent->type = NTRIP_SOURCE_AGENT;
                TAILQ_INSERT_TAIL(&agent->caster->agents_head[agent->type], agent, entries);
                agent->caster->agents_cnt[agent->type] += 1;
                LOG_INFO("move agent(%d) into source agents", agent->socket);
                return;
            }
            // not matching
        } while(0);
        // error occurs, stop and close agent
        LOG_INFO("agent(%d) request error", agent->socket);
        ev_io_stop(EV_A_ &agent->io);
        close_agent(agent);
    } else if (agent->type == NTRIP_CLIENT_AGENT) {
        // ntrip client read
        // now will read and discard client gga message
        char buf[512];
        int n = recv(agent->socket, buf, sizeof(buf) - 1, 0);
        if (n == WSOCKET_ERROR && wsocket_errno != WSOCKET_EWOULDBLOCK) {
            LOG_ERROR("agent(%d) recv error, %s", agent->socket, wsocket_strerror(wsocket_errno));
            ev_io_stop(EV_A_ &agent->io);
            close_agent(agent);
            return;
        }
        if (n == 0) {
            LOG_INFO("agent(%d) connection close", agent->socket);
            ev_io_stop(EV_A_ &agent->io);
            close_agent(agent);
            return;
        }
        if (n < 0) { // maybe -1 since WSOCKET_EWOULDBLOCK
            return;
        }
        agent->in_bytes += n;
        agent->in_bps = n * 8;
        agent->last_activity = ev_now(EV_A);
        // discard client data
    } else if (agent->type == NTRIP_SOURCE_AGENT) {
        // ntrip server read
        char buf[512];
        int n = recv(agent->socket, buf, sizeof(buf) - 1, 0);
        if (n == WSOCKET_ERROR && wsocket_errno != WSOCKET_EWOULDBLOCK) {
            LOG_ERROR("agent(%d) recv error, %s", agent->socket, wsocket_strerror(wsocket_errno));
            ev_io_stop(EV_A_ &agent->io);
            close_agent(agent);
            return;
        }
        if (n == 0) {
            LOG_INFO("agent(%d) connection close", agent->socket);
            ev_io_stop(EV_A_ &agent->io);
            close_agent(agent);
            return;
        }
        if (n < 0) { // maybe -1 since WSOCKET_EWOULDBLOCK
            return;
        }
        agent->in_bytes += n;
        agent->in_bps = n * 8;
        agent->last_activity = ev_now(EV_A);
        // send data to every match mountpoint clients
        struct ntrip_agent *client, *temp;
        TAILQ_FOREACH_SAFE(client, &agent->caster->agents_head[NTRIP_CLIENT_AGENT], entries, temp) {
            if (strcasecmp(agent->mountpoint, client->mountpoint) == 0) {
                if (send(client->socket, buf, n, 0) != WSOCKET_ERROR) {
                    client->out_bytes += n;
                    client->out_bps = n * 8;
                    client->last_activity = ev_now(EV_A);
                }
            }
        }
    } else {
        LOG_ERROR("close error type agent(%d, type=%d) from %s",
                  agent->socket, agent->type, agent->peeraddr);
        ev_io_stop(EV_A_ &agent->io);
        wsocket_close(agent->socket);
        free(agent);
    }
}


static void caster_accept_cb(EV_P_ ev_io *w, int revents)
{
    struct ntrip_caster* caster = (struct ntrip_caster *)w;
    wsocket agent_socket = INVALID_WSOCKET;
    struct sockaddr_storage agent_addr = {0};
    socklen_t agent_addrlen = sizeof(agent_addr);

    struct ntrip_agent *agent = NULL;

    if (EV_ERROR & revents) {
        LOG_ERROR("invalid ev event with error");
        return;
    }

    agent_socket = accept(caster->socket, (struct sockaddr *)&agent_addr, &agent_addrlen);
    if (agent_socket == INVALID_WSOCKET) {
        LOG_ERROR("accept() error, %s", wsocket_strerror(wsocket_errno));
        return;
    }
    // set nonblocking
    wsocket_set_nonblocking(agent_socket);
    // print connect info
    char addrbuf[NI_MAXHOST] = {0};
    char servbuf[NI_MAXSERV] = {0};
    int rv = 0;
    if ((rv = getnameinfo((struct sockaddr *)&agent_addr, agent_addrlen,
                          addrbuf, sizeof(addrbuf),
                          servbuf, sizeof(servbuf),
                          NI_NUMERICHOST | NI_NUMERICSERV)) == 0) {
        LOG_INFO("accept agent(%d) from %s:%s", agent_socket, addrbuf, servbuf);

    } else {
        LOG_ERROR("getnameinfo() error, %s", gai_strerror(rv));
    }
    // check if pending agents max count
    if (caster->config.MAX_PENDING_CNT > 0 &&
        caster->config.MAX_PENDING_CNT <= caster->agents_cnt[NTRIP_PENDING_AGENT]) {
        LOG_WARN("too many pending agents, now=%zu, MAX=%zu",
                 caster->agents_cnt[NTRIP_PENDING_AGENT],
                 caster->config.MAX_PENDING_CNT);
        LOG_INFO("reject agent(%d) from %s:%s", agent_socket, addrbuf, servbuf);
        wsocket_close(agent_socket);
        return;
    }
    agent = calloc(1, sizeof(*agent));
    if (agent == NULL) {
        LOG_ERROR("malloc() error, %s", strerror(errno));
        return;
    }
    agent->socket = agent_socket;
    agent->type = NTRIP_PENDING_AGENT;
    agent->mountpoint[0] = '\0';
    snprintf(agent->peeraddr, sizeof(agent->peeraddr), "%s", addrbuf);
    agent->user_agent[0] = '\0';
    agent->login_time = time(NULL);
    agent->last_activity = ev_now(EV_A);
    agent->pending_idx = 0;
    agent->caster = caster;

    ev_io_init(&agent->io, agent_read_cb, WSOCKET_GET_FD(agent_socket), EV_READ);
    TAILQ_INSERT_TAIL(&caster->agents_head[NTRIP_PENDING_AGENT], agent, entries);
    caster->agents_cnt[NTRIP_PENDING_AGENT] += 1;

    ev_io_start(EV_A_  &agent->io);
}

static void caster_timeout_cb(EV_P_ ev_timer *w, int revents)
{
#define TRAFFIC_STATUS_FMT "%-8s %-8s %-16s %-5zu %-8zu %s"
    // check and remove non-active agent
    // output clients and servers traffic
    struct ntrip_caster *caster = (struct ntrip_caster *)((char *)w - offsetof(struct ntrip_caster, timer));
    ev_tstamp now = ev_now(EV_A);
    struct ntrip_agent *agent, *temp;
    LOG_TRACE("======= Current clients/servers status ========");
    LOG_TRACE("%-8s %-8s %-16s %-5s %-8s %s", "Type", "MountP", "From", "Bps", "Bytes", "UserAgent");
    for (int i = 0; i < NTRIP_AGENT_SENTRY; i++) {
        TAILQ_FOREACH_SAFE(agent, &caster->agents_head[i], entries, temp) {
            if (i == NTRIP_CLIENT_AGENT) {
                LOG_TRACE(TRAFFIC_STATUS_FMT,
                          "Client", agent->mountpoint, agent->peeraddr,
                          agent->out_bps, agent->out_bytes, agent->user_agent);
            } else if (i == NTRIP_SOURCE_AGENT) {
                LOG_TRACE(TRAFFIC_STATUS_FMT,
                          "Source", agent->mountpoint, agent->peeraddr,
                          agent->in_bps, agent->in_bytes, agent->user_agent);
            }
            if (now - agent->last_activity >= 10.0) {
                LOG_INFO("timeout agent(%d) from %s", agent->socket, agent->peeraddr);
                ev_io_stop(EV_A_ &agent->io);
                close_agent(agent);
            }
        }
    }
}

static void caster_init_config(struct ntrip_caster_config *config)
{
    // init default
    config->MAX_PENDING_CNT = DEFAULT_MAX_PENDING_AGENT;
    config->MAX_CLIENT_CNT  = DEFAULT_MAX_CLIENT_AGENT;
    config->MAX_SOURCE_CNT  = DEFAULT_MAX_SOURCE_AGENT;
    TAILQ_INIT(&config->client_token_head);
    TAILQ_INIT(&config->source_token_head);
    snprintf(config->bind_addr, sizeof(config->bind_addr), "%s", "0.0.0.0");
    snprintf(config->bind_serv, sizeof(config->bind_serv), "%d", 2101);
    // TODO: read from config file
}

int main(int argc, const char *argv[])
{
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    WSOCKET_INIT();
    struct ev_loop* loop = EV_DEFAULT;
    struct ntrip_caster caster = {0};
    // init caster config
    caster_init_config(&caster.config);
    for (int i = 0; i < NTRIP_AGENT_SENTRY; i++) {
        caster.agents_cnt[i] = 0;
        TAILQ_INIT(&caster.agents_head[i]);
    }

    wsocket sock = listen_on(caster.config.bind_addr, caster.config.bind_serv);
    if (sock == INVALID_WSOCKET) {
        LOG_ERROR("setup server error.");
        return 1;
    } else {
        LOG_INFO("setup server on %s:%s OK.", caster.config.bind_addr, caster.config.bind_serv);
    }

    caster.socket = sock;
    ev_io_init(&caster.io, caster_accept_cb, WSOCKET_GET_FD(sock), EV_READ);
    ev_io_start(EV_A_ &caster.io);
    ev_timer_init(&caster.timer, caster_timeout_cb, 5, 5);
    ev_timer_start(EV_A_ &caster.timer);

    while (1) {
        ev_loop(loop, 0);
    }

    WSOCKET_CLEANUP();
    return 0;
}
