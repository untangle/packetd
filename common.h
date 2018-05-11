/**
 * common.h
 *
 * Shared cgo variables and functions for the Untangle Packet Daemon
 *
 * Copyright (c) 2018 Untangle, Inc.
 * All Rights Reserved
 */

#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/netfilter.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <libnfnetlink/libnfnetlink.h>
/*--------------------------------------------------------------------------*/
static struct timeval   g_runtime;
static int              g_shutdown;
static int              g_debug;
/*--------------------------------------------------------------------------*/
static void common_startup(void)
{
    gettimeofday(&g_runtime,NULL);
    g_shutdown = 0;
    g_debug = 1;
}
/*--------------------------------------------------------------------------*/
static char* itolevel(int value,char *dest)
{
    if (value == LOG_EMERG)     return(strcpy(dest,"EMERGENCY"));
    if (value == LOG_ALERT)     return(strcpy(dest,"ALERT"));
    if (value == LOG_CRIT)      return(strcpy(dest,"CRITICAL"));
    if (value == LOG_ERR)       return(strcpy(dest,"ERROR"));
    if (value == LOG_WARNING)   return(strcpy(dest,"WARNING"));
    if (value == LOG_NOTICE)    return(strcpy(dest,"NOTICE"));
    if (value == LOG_INFO)      return(strcpy(dest,"INFO"));
    if (value == LOG_DEBUG)     return(strcpy(dest,"DEBUG"));

    sprintf(dest,"LOG_%d",value);
    return(dest);
}
/*--------------------------------------------------------------------------*/
static void rawmessage(int priority,const char *message)
{
    struct timeval  nowtime;
    struct tm       *today;
    time_t          value;
    double          rr,nn,ee;
    char            string[32];

    if ((priority == LOG_DEBUG) && (g_debug == 0)) return;

    gettimeofday(&nowtime,NULL);

    rr = ((double)g_runtime.tv_sec * (double)1000000.00);
    rr+=(double)g_runtime.tv_usec;

    nn = ((double)nowtime.tv_sec * (double)1000000.00);
    nn+=(double)nowtime.tv_usec;

    ee = ((nn - rr) / (double)1000000.00);

    itolevel(priority,string);
    printf("[%.6f] %s %s",ee,string,message);

    fflush(stdout);
    return;
}
/*--------------------------------------------------------------------------*/
static void logmessage(int priority,const char *format,...)
{
    va_list         args;
    char            message[1024];

    if ((priority == LOG_DEBUG) && (g_debug == 0)) return;

    va_start(args,format);
    vsnprintf(message,sizeof(message),format,args);
    va_end(args);

    rawmessage(priority,message);
}
/*--------------------------------------------------------------------------*/
static void hexmessage(int priority,const void *buffer,int size)
{
    const unsigned char     *data;
    char                    *message;
    int                     loc;
    int                     x;

    if ((priority == LOG_DEBUG) && (g_debug == 0)) return;

    message = (char *)malloc((size * 3) + 4);
    data = (const unsigned char *)buffer;

    for (x = 0;x < size;x++) {
        loc = (x * 3);
        if (x == 0) sprintf(&message[loc],"%02X ",data[x]);
        else sprintf(&message[loc],"%02X ",data[x]);
    }

    loc = (size * 3);
    strcpy(&message[loc],"\n");
    rawmessage(priority,message);
    free(message);
}
/*--------------------------------------------------------------------------*/
static int get_shutdown_flag(void)
{
    return(g_shutdown);
}
/*--------------------------------------------------------------------------*/

