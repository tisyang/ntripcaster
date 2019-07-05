#ifndef LOG_H
#define LOG_H

// simple log macros in a single header file
// Author by TyK
// Link: https://github.com/lazytinker/log.h

#include <stdio.h>

#define LOG_TERM_COLOR

// terminal color
#ifdef LOG_TERM_COLOR
# define COLOR_TRACE   "\x1b[94m"
# define COLOR_DEBUG   "\x1b[36m"
# define COLOR_INFO    "\x1b[32m"
# define COLOR_WARN    "\x1b[33m"
# define COLOR_ERROR   "\x1b[31m"
# define COLOR_RESET   "\x1b[0m"
#else
# define COLOR_TRACE
# define COLOR_DEBUG
# define COLOR_INFO
# define COLOR_WARN
# define COLOR_ERROR
# define COLOR_RESET
#endif

// ## __VA_ARGS__ will remove the leading comma if __VA_ARGS__ is empty.
#define LOG_TRACE(fmt, ...) fprintf(stdout, COLOR_TRACE "[TRACE] " COLOR_RESET fmt "\n", ## __VA_ARGS__)
#define LOG_DEBUG(fmt, ...) fprintf(stdout, COLOR_DEBUG "[DEBUG] " COLOR_RESET fmt "\n", ## __VA_ARGS__)
#define LOG_INFO(fmt, ...)  fprintf(stdout, COLOR_INFO  "[INFO ] " COLOR_RESET fmt "\n", ## __VA_ARGS__)
#define LOG_WARN(fmt, ...)  fprintf(stdout, COLOR_WARN  "[WARN ] " COLOR_RESET fmt "\n", ## __VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, COLOR_ERROR "[ERROR] " COLOR_RESET fmt "\n", ## __VA_ARGS__)


#endif // LOG_H

