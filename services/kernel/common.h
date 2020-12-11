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
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <libnfnetlink/libnfnetlink.h>

#define LOG_TRACE	LOG_DEBUG+1

/*
 * We have a single set of variables for the orig and repl source and
 * destination addresses that are large enough to hold either an IPv4
 * or an IPv6 address. The callback handler will extract the correct
 * data and fill them based on the value of family (AF_INET or AF_INET6)
 */
struct conntrack_info {
	u_int32_t		conn_id;
	u_int8_t		msg_type;
	u_int8_t		family;
	u_int8_t		orig_proto;
	u_int8_t		tcp_state;
	char			orig_saddr[16];
	char			orig_daddr[16];
	char			repl_saddr[16];
	char			repl_daddr[16];
	u_int16_t		orig_sport;
	u_int16_t		orig_dport;
	u_int16_t		repl_sport;
	u_int16_t		repl_dport;
	u_int64_t		orig_bytes;
	u_int64_t		repl_bytes;
	u_int64_t		orig_packets;
	u_int64_t		repl_packets;
	u_int64_t		timestamp_start;
	u_int64_t		timestamp_stop;
	u_int32_t		conn_mark;
	u_int32_t		timeout;
};

/*
 * The src_addr and dst_addr fields are large enough to
 * hold either an IPv4 or IPv6 address in human readable
 * format, rounded up to a nice even value. Note that
 * an IPv6 address could be as long as 45 characters in
 * the case of IPv4-mapped IPv6 address (45 characters):
 * ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:101.102.103.104
 */
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
	u_int32_t		ctid;
	char			prefix[256];
};

struct nfq_data {
	struct nfattr	**data;
};

struct nflog_data {
	struct nfattr	**nfa;
};

extern void go_nfqueue_callback(uint32_t mark,unsigned char* data,int len,uint32_t ctid,uint32_t nfid,uint32_t family,char* memory,int playflag,int index);
extern void go_netlogger_callback(struct netlogger_info* info,int playflag);
extern void go_conntrack_callback(struct conntrack_info* info,int playflag);

extern void go_child_startup(void);
extern void go_child_shutdown(void);
extern void go_child_message(int level,char *source,char *message);

extern int32_t go_get_shutdown_flag();
extern void go_set_shutdown_flag();

void common_startup(void);
void common_shutdown(void);
char* itolevel(int value,char *dest);
void rawmessage(int priority,const char *source,const char *message);
void logmessage(int priority,const char *source,const char *format,...);
void hexmessage(int priority,const char *source,const void *buffer,int size);

int get_shutdown_flag(void);
void set_shutdown_flag(void);

int get_bypass_flag(void);
void set_bypass_flag(int value);

int get_warehouse_flag(void);
void set_warehouse_flag(int value);
void set_warehouse_file(char *filename);
char *get_warehouse_file(void);
int get_warehouse_speed(void);
void set_warehouse_speed(int value);
void start_warehouse_capture(void);
void close_warehouse_capture(void);

int conntrack_startup(void);
void conntrack_shutdown(void);
int conntrack_thread(void);
void conntrack_dump(void);
int conntrack_update_mark(uint32_t ctid, uint32_t mask, uint32_t value);

int nfq_get_ct_info(struct nfq_data *nfad, unsigned char **data);
uint32_t nfq_get_conntrack_id(struct nfq_data *nfad, int l3num);
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data);
int nfqueue_set_verdict(int index, uint32_t nfid, uint32_t verdict);
int nfqueue_startup(int index);
void nfqueue_shutdown(int index);
int nfqueue_thread(int index);
void nfqueue_free_buffer(char *buffer);

int netlogger_callback(struct nflog_g_handle *gh,struct nfgenmsg *nfmsg,struct nflog_data *nfa,void *data);
int netlogger_startup(void);
void netlogger_shutdown(void);
int netlogger_thread(void);
void netlogger_shutdown(void);

int warehouse_startup(void);
void warehouse_shutdown(void);
void warehouse_capture(const char origin,void *buffer,uint32_t length,uint32_t mark,uint32_t ctid,uint32_t nfid,uint32_t family);
void warehouse_playback(void);
struct timespec calculate_pause(struct timespec start,struct timespec end,int speed);

void bypass_via_nft_set(uint32_t ctid, uint64_t timeout);
