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
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/netfilter.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <libnfnetlink/libnfnetlink.h>

// FIXME IPv6
struct conntrack_info {
	u_int8_t		msg_type;
	u_int32_t		conn_id;
	u_int8_t		orig_proto;
	u_int32_t		orig_saddr;
	u_int32_t		orig_daddr;
	u_int16_t		orig_sport;
	u_int16_t		orig_dport;
	u_int32_t		repl_saddr;
	u_int32_t		repl_daddr;
	u_int16_t		repl_sport;
	u_int16_t		repl_dport;
	u_int64_t		orig_bytes;
	u_int64_t		repl_bytes;
};

struct netlogger_info {
	u_int8_t		version;
	u_int8_t		protocol;
	u_int16_t		icmp_type;
	u_int8_t		src_intf;
	u_int8_t		dst_intf;
	char			src_addr[64];
	char			dst_addr[64];
	u_int16_t		src_port;
	u_int16_t		dst_port;
	u_int32_t		mark;
	char			prefix[64];
};

struct nfq_data {
	struct nfattr	**data;
};

extern void go_nfqueue_callback(uint32_t mark,unsigned char* data,int len,uint32_t ctid,uint32_t nfid,unsigned char* buffer);
extern void go_netlogger_callback(struct netlogger_info* info);
extern void go_conntrack_callback(struct conntrack_info* info);
extern void go_child_startup(void);
extern void go_child_shutdown(void);
extern void go_child_message(int level,char *source,char *message);

void common_startup(void);
void common_shutdown(void);
char* itolevel(int value,char *dest);
void rawmessage(int priority,const char *source,const char *message);
void logmessage(int priority,const char *source,const char *format,...);
void hexmessage(int priority,const char *source,const void *buffer,int size);
int get_shutdown_flag(void);
void set_shutdown_flag(int value);

int conntrack_startup(void);
void conntrack_shutdown(void);
int conntrack_thread(void);
void conntrack_shutdown(void);
void conntrack_dump(void);

int nfq_get_ct_info(struct nfq_data *nfad, unsigned char **data);
uint32_t nfq_get_conntrack_id(struct nfq_data *nfad, int l3num);
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data);
int nfqueue_set_verdict(uint32_t nfid, uint32_t verdict, uint32_t mark);
void nfqueue_free_buffer(unsigned char* buffer);
int nfqueue_startup(void);
void nfqueue_shutdown(void);
int nfqueue_thread(void);
void nfqueue_shutdown(void);

int netlogger_callback(struct nflog_g_handle *gh,struct nfgenmsg *nfmsg,struct nflog_data *nfa,void *data);
int netlogger_startup(void);
void netlogger_shutdown(void);
int netlogger_thread(void);
void netlogger_shutdown(void);

