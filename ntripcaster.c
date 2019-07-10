#include <time.h>
#include "logh/log.h"
#include "wsocket/wsocket.h"
#include "queue.h"

#include <ev.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

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
    char username[32];          // agent ntrip username(valid for ntrip client)
    char mountpoint[128];       // mountpoint requested by agent
    char peeraddr[NI_MAXHOST];  // agent ip address
    char user_agent[64];        // agent ntrip user agent string
    time_t login_time;          // agent login time
    ev_tstamp last_activity;    // agent last IO time

    struct ntrip_caster* caster; // agent associate caster(not change during whole agent lifetime)
    TAILQ_ENTRY(ntrip_agent) entries;  // agent list
};

struct ntrip_caster {
    ev_io io;
    ev_timer timer; // timer for check agent alive
    wsocket socket;
    TAILQ_HEAD(, ntrip_agent) m_agents_head[NTRIP_AGENT_SENTRY]; // agent list for PENDING/CLIENT/SOURCE
};

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
    if (agent->type >= NTRIP_PENDING_AGENT && agent->type < NTRIP_AGENT_SENTRY) {
        TAILQ_REMOVE(&agent->caster->m_agents_head[agent->type], agent, entries);
    }
    LOG_INFO("close agent(%d) from %s", agent->socket, agent->peeraddr);
    wsocket_close(agent->socket);
    free(agent);
}

static void agent_read_cb(EV_P_ ev_io *w, int revents)
{
#define WARN "YOU CAN NO SEND DATA\n"
    struct ntrip_agent *agent = (struct ntrip_agent *)w;
    if (agent->type >= NTRIP_PENDING_AGENT && agent->type < NTRIP_AGENT_SENTRY) {
        send(agent->socket, WARN, strlen(WARN), 0);
        ev_io_stop(EV_A_ &agent->io);
        close_agent(agent);
    } else {
        LOG_ERROR("error agent type=%d", agent->type);
        ev_io_stop(EV_A_ &agent->io);
        close_agent(agent);
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
    agent = calloc(1, sizeof(*agent));
    if (agent == NULL) {
        LOG_ERROR("malloc() error, %s", strerror(errno));
        return;
    }
    agent->socket = agent_socket;
    agent->type = NTRIP_PENDING_AGENT;
    agent->username[0] = '\0';
    agent->mountpoint[0] = '\0';
    snprintf(agent->peeraddr, sizeof(agent->peeraddr), "%s", addrbuf);
    agent->user_agent[0] = '\0';
    agent->login_time = time(NULL);
    agent->last_activity = agent->login_time;
    agent->caster = caster;

    ev_io_init(&agent->io, agent_read_cb, WSOCKET_GET_FD(agent_socket), EV_READ);
    TAILQ_INSERT_TAIL(&caster->m_agents_head[NTRIP_PENDING_AGENT], agent, entries);

    ev_io_start(EV_A_  &agent->io);
}

static void caster_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    // TODO:
    LOG_DEBUG("caster timer triggered");
}

int main(int argc, const char *argv[])
{
    WSOCKET_INIT();
    struct ev_loop* loop = EV_DEFAULT;
    struct ntrip_caster caster = {0};
    for (int i = 0; i < NTRIP_AGENT_SENTRY; i++) {
        TAILQ_INIT(&caster.m_agents_head[i]);
    }

    wsocket sock = listen_on(NULL, "1024");
    if (sock == INVALID_WSOCKET) {
        LOG_ERROR("setup server error.");
        return 1;
    } else {
        LOG_INFO("setup server on 1024 OK.");
    }

    caster.socket = sock;
    ev_io_init(&caster.io, caster_accept_cb, WSOCKET_GET_FD(sock), EV_READ);
    ev_io_start(EV_A_ &caster.io);
    ev_timer_init(&caster.timer, caster_timeout_cb, 5, 5);
    ev_timer_start(EV_A_ &caster.timer);

    while (1) {
        ev_run(loop, 0);
    }

    WSOCKET_CLEANUP();
    return 0;
}
