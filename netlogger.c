/**
 * netlogger.c
 *
 * Handles receiving netfilter log events for the Untnagle Packet Daemon
 *
 * Copyright (c) 2018 Untangle, Inc.
 * All Rights Reserved
 */

#include "common.h"
/*--------------------------------------------------------------------------*/
static struct nflog_handle		*l_log_handle;
static struct nflog_g_handle	*l_grp_handle;
static int						l_logsock;
static char                     *appname = "netlogger";
/*--------------------------------------------------------------------------*/
int netlogger_callback(struct nflog_g_handle *gh,struct nfgenmsg *nfmsg,struct nflog_data *nfa,void *data)
{
	struct netlogger_info	info;
	struct icmphdr			*icmphead;
	struct tcphdr			*tcphead;
	struct udphdr			*udphead;
	struct iphdr			*iphead;
	char					*packet_data;
	int						packet_size;

	// get the raw packet and check for sanity
	packet_size = nflog_get_payload(nfa,&packet_data);
	if ((packet_data == NULL) || (packet_size < 20)) return(0);

	// get the prefix string
	info.prefix = nflog_get_prefix(nfa);
	if (info.prefix == NULL) info.prefix = "";

	// get the mark and parse the source and dest interfaces
	info.mark = nflog_get_nfmark(nfa);
	info.src_intf = (info.mark & 0xFF);
	info.dst_intf = ((info.mark & 0xFF00) >> 8);

	// set up the IP, TCP, and UDP headers for parsing
	iphead = (struct iphdr *)packet_data;
	tcphead = (struct tcphdr *)&packet_data[iphead->ihl << 2];
	udphead = (struct udphdr *)&packet_data[iphead->ihl << 2];
	icmphead = (struct icmphdr *)&packet_data[iphead->ihl << 2];

	// grab the protocol
	info.protocol = iphead->protocol;

	// grab the source and destination addresses
	info.src_addr = iphead->saddr;
	info.dst_addr = iphead->daddr;

	// Since 0 is a valid ICMP type we use 999 to signal null or unknown
	info.src_port = info.dst_port = 0;
	info.icmp_type = 999;

	switch (info.protocol) {
	case IPPROTO_ICMP:
		info.icmp_type = icmphead->type;
		break;
	case IPPROTO_TCP:
		info.src_port = ntohs(tcphead->source);
		info.dst_port = ntohs(tcphead->dest);
		break;
	case IPPROTO_UDP:
		info.src_port = ntohs(udphead->source);
		info.dst_port = ntohs(udphead->dest);
		break;
	}

	go_netlogger_callback(&info);

	return(0);
}
/*--------------------------------------------------------------------------*/
int netlogger_startup(void)
{
	int		ret;

	// open a log handle to the netfilter log library
	l_log_handle = nflog_open();

	if (l_log_handle == NULL) {
		logmessage(LOG_ERR,appname,"Error %d returned from nflog_open()\n",errno);
		return(1);
	}

	// unbind any existing AF_INET handler
	ret = nflog_unbind_pf(l_log_handle,AF_INET);

	if (ret < 0) {
		logmessage(LOG_ERR,appname,"Error %d returned from nflog_unbind_pf()\n",errno);
		return(2);
	}

	// bind us as the AF_INET handler
	ret = nflog_bind_pf(l_log_handle,AF_INET);

	if (ret < 0) {
		logmessage(LOG_ERR,appname,"Error %d returned from nflog_bind_pf()\n",errno);
		return(3);
	}

	// bind our log handle to group zero
	l_grp_handle = nflog_bind_group(l_log_handle,0);

	if (l_grp_handle == NULL) {
		logmessage(LOG_ERR,appname,"Error %d returned from nflog_bind_group()\n",errno);
		return(4);
	}

	// give the log plenty of buffer space
	ret = nflog_set_nlbufsiz(l_grp_handle,0x8000);
	if (ret < 0) {
		logmessage(LOG_ERR,appname,"Error %d returned from nflog_set_nlbufsiz()\n",errno);
		return(5);
	}

	// set copy packet mode to give us the first 256 bytes
	ret = nflog_set_mode(l_grp_handle,NFULNL_COPY_PACKET,256);

	if (ret < 0) {
		logmessage(LOG_ERR,appname,"Error %d returned from nflog_set_mode()\n",errno);
		return(6);
	}

	// get a file descriptor for our log handle
	l_logsock = nflog_fd(l_log_handle);

	// register callback for our group handle
	nflog_callback_register(l_grp_handle,&netlogger_callback,NULL);

	return(0);
}
/*--------------------------------------------------------------------------*/
void netlogger_shutdown(void)
{
	int		ret;

	// unbind from our group
	if (l_grp_handle != NULL) {
		ret = nflog_unbind_group(l_grp_handle);
		if (ret < 0) logmessage(LOG_ERR,appname,"Error %d returned from nflog_unbind_group()\n",errno);
	}

	// close our log handle
	if (l_log_handle != NULL) {
		ret = nflog_close(l_log_handle);
		if (ret < 0) logmessage(LOG_ERR,appname,"Error %d returned from nflog_close()\n",errno);
	}
}
/*--------------------------------------------------------------------------*/
int netlogger_thread(void)
{
	struct timeval	tv;
	fd_set			tester;
	char			buffer[4096];
	int				ret;

	logmessage(LOG_INFO,appname,"The netlogger thread is starting\n");

	// call our logger startup function
	ret = netlogger_startup();

	// if there were any startup errors set the shutdown flag
	if (ret != 0) {
		logmessage(LOG_ERR,appname,"Error %d returned from netlogger_startup(init)\n",ret);
		set_shutdown_flag(1);
	}

	go_child_startup();

	// sit in this loop processing messages from the queue
	while (get_shutdown_flag() == 0) {
		// clear the select set and add the log socket
		FD_ZERO(&tester);
		FD_SET(l_logsock,&tester);

		// wait for some log data
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		ret = select(l_logsock+1,&tester,NULL,NULL,&tv);
		if (ret < 1) continue;

		// read the log data
		ret = recv(l_logsock,buffer,sizeof(buffer),0);

		// recycle connection on error
		if (ret < 0) {
			logmessage(LOG_ERR,appname,"Error %d returned from recv() - Recycling nflog connection\n",errno);
			netlogger_shutdown();
			sleep(1000);
			ret = netlogger_startup();

			// if startup failed log the error and set the shutdown flag
			if (ret != 0) {
				logmessage(LOG_ERR,appname,"Error %d returned from netlogger_startup(loop)\n",ret);
				set_shutdown_flag(1);
				break;
			}
		}

		// no error so do the packet handling
		else {
			nflog_handle_packet(l_log_handle,buffer,ret);
		}
	}

	// call our logger shutdown function
	netlogger_shutdown();

	logmessage(LOG_INFO,appname,"The netlogger thread has terminated\n");
	go_child_goodbye();
	return(0);
}
/*--------------------------------------------------------------------------*/
void netlogger_goodbye(void)
{
	set_shutdown_flag(1);
}
/*--------------------------------------------------------------------------*/
