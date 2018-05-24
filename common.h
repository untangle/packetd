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
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/netfilter.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <libnfnetlink/libnfnetlink.h>
/*--------------------------------------------------------------------------*/
struct conntrack_info {
	u_int8_t		msg_type;
	u_int32_t		conn_id;
	u_int8_t		orig_proto;
	u_int32_t		orig_saddr;
	u_int32_t		orig_daddr;
	u_int16_t		orig_sport;
	u_int16_t		orig_dport;
	u_int64_t		orig_bytes;
	u_int64_t		repl_bytes;
};
/*--------------------------------------------------------------------------*/
struct netlogger_info {
	u_int8_t		protocol;
	u_int16_t		icmp_type;
	u_int8_t		src_intf, dst_intf;
	u_int32_t		src_addr, dst_addr;
	u_int16_t		src_port, dst_port;
	u_int32_t		mark;
	const char		*prefix;
};
/*--------------------------------------------------------------------------*/
struct nfq_data {
	struct nfattr	**data;
};
/*--------------------------------------------------------------------------*/
extern unsigned int go_netfilter_callback(unsigned int mark,unsigned char* data,int len,unsigned int ctid);
extern void go_netlogger_callback(struct netlogger_info* info);
extern void go_conntrack_callback(struct conntrack_info* info);
extern void go_child_startup(void);
extern void go_child_goodbye(void);
extern void go_child_message(int level,char *source,char *message);
/*--------------------------------------------------------------------------*/
void common_startup(void);
void common_goodbye(void);
char* itolevel(int value,char *dest);
void rawmessage(int priority,const char *source,const char *message);
void logmessage(int priority,const char *source,const char *format,...);
void hexmessage(int priority,const char *source,const void *buffer,int size);
int get_shutdown_flag(void);
void set_shutdown_flag(int value);
/*--------------------------------------------------------------------------*/
int conntrack_startup(void);
void conntrack_shutdown(void);
int conntrack_thread(void);
void conntrack_goodbye(void);
void conntrack_dump(void);
/*--------------------------------------------------------------------------*/
int nfq_get_ct_info(struct nfq_data *nfad, unsigned char **data);
unsigned int nfq_get_conntrack_id(struct nfq_data *nfad, int l3num);
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data);
int netfilter_startup(void);
void netfilter_shutdown(void);
int netfilter_thread(void);
void netfilter_goodbye(void);
/*--------------------------------------------------------------------------*/
int netlogger_callback(struct nflog_g_handle *gh,struct nfgenmsg *nfmsg,struct nflog_data *nfa,void *data);
int netlogger_startup(void);
void netlogger_shutdown(void);
int netlogger_thread(void);
void netlogger_goodbye(void);
/*--------------------------------------------------------------------------*/
