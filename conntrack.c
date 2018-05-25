/**
 * conntrack.c
 *
 * Handles receiving conntrack updates for the Untnagle Packet Daemon
 *
 * Copyright (c) 2018 Untangle, Inc.
 * All Rights Reserved
 */

#include "common.h"
/*--------------------------------------------------------------------------*/
static struct nfct_handle	*nfcth;
static u_int64_t			tracker_error;
static u_int64_t			tracker_unknown;
static char                 *appname = "conntrack";
/*--------------------------------------------------------------------------*/
static int conntrack_callback(enum nf_conntrack_msg_type type,struct nf_conntrack *ct,void *data)
{
	struct conntrack_info	info;

	// if the shutdown flag is set return stop to interrupt nfct_catch
	if (get_shutdown_flag() != 0) return(NFCT_CB_STOP);

	switch (type) {
	case NFCT_T_NEW:
		info.msg_type = 'N';
		break;
	case NFCT_T_UPDATE:
		info.msg_type = 'U';
		break;
	case NFCT_T_DESTROY:
		info.msg_type = 'D';
		break;
	case NFCT_T_ERROR:
		tracker_error++;
		return(NFCT_CB_CONTINUE);
	default:
		tracker_unknown++;
		return(NFCT_CB_CONTINUE);
	}

	info.orig_proto = nfct_get_attr_u8(ct,ATTR_ORIG_L4PROTO);

	// ignore everything except TCP and UDP
	if ((info.orig_proto != IPPROTO_TCP) && (info.orig_proto != IPPROTO_UDP)) return(NFCT_CB_CONTINUE);

	// get the conntrack ID
	info.conn_id = nfct_get_attr_u32(ct, ATTR_ID);

	// get the source and destination addresses
	info.orig_saddr = nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC);
	info.orig_daddr = nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_DST);

	// ignore anything on the loopback interface by looking at the least
	// significant byte because these values are in network byte order
	if ((info.orig_saddr & 0x000000FF) == 0x0000007F) return(NFCT_CB_CONTINUE);
	if ((info.orig_daddr & 0x000000FF) == 0x0000007F) return(NFCT_CB_CONTINUE);

	// get all of the source and destination ports
	info.orig_sport = be16toh(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC));
	info.orig_dport = be16toh(nfct_get_attr_u16(ct,ATTR_ORIG_PORT_DST));

	// get the byte counts
	info.orig_bytes = nfct_get_attr_u64(ct,ATTR_ORIG_COUNTER_BYTES);
	info.repl_bytes = nfct_get_attr_u64(ct,ATTR_REPL_COUNTER_BYTES);

	go_conntrack_callback(&info);

	return(NFCT_CB_CONTINUE);
}
/*--------------------------------------------------------------------------*/
int conntrack_startup(void)
{
	int		ret;

	// Open a netlink conntrack handle. The header file defines
	// NFCT_ALL_CT_GROUPS but we really only care about new and
	// destroy so we subscribe to just those ignoring update
	nfcth = nfct_open(CONNTRACK,NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY);

	if (nfcth == NULL) {
		logmessage(LOG_ERR,appname,"Error %d returned from nfct_open()\n",errno);
		set_shutdown_flag(1);
		return(1);
	}

	// register the conntrack callback
	ret = nfct_callback_register(nfcth,NFCT_T_ALL,conntrack_callback,NULL);

	if (ret != 0) {
		logmessage(LOG_ERR,appname,"Error %d returned from nfct_callback_register()\n",errno);
		set_shutdown_flag(1);
		return(2);
	}

	return(0);
}
/*--------------------------------------------------------------------------*/
void conntrack_shutdown(void)
{
	if (nfcth == NULL) return;

	// unregister the callback handler
	nfct_callback_unregister(nfcth);

	// close the conntrack netlink handler
	nfct_close(nfcth);

	// clear our conntrack handle
	nfcth = NULL;
}
/*--------------------------------------------------------------------------*/
int conntrack_thread(void)
{
	int		ret;

	logmessage(LOG_INFO,appname,"The conntrack thread is starting\n");

	// call our conntrack startup function
	ret = conntrack_startup();

	if (ret != 0) {
		logmessage(LOG_ERR,appname,"Error %d returned from conntrack_startup()\n",ret);
		set_shutdown_flag(1);
		return(1);
	}

	go_child_startup();

	// the nfct_catch function should only return if it receives a signal
	// other than EINTR or if NFCT_CB_STOP is returned from the callback
	while (get_shutdown_flag() == 0) {
		nfct_catch(nfcth);
	}

	// call our conntrack shutdown function
	conntrack_shutdown();

	logmessage(LOG_INFO,appname,"The conntrack thread has terminated\n");
	go_child_goodbye();
	return(0);
}
/*--------------------------------------------------------------------------*/
void conntrack_goodbye(void)
{
	u_int32_t	family;

	set_shutdown_flag(1);
	if (nfcth == NULL) return;

	// dump the conntrack table to interrupt the nfct_catch function
	family = AF_INET;
	nfct_send(nfcth,NFCT_Q_DUMP,&family);
}
/*--------------------------------------------------------------------------*/
void conntrack_dump(void)
{
	u_int32_t	family;
	int			ret;

	if (nfcth == NULL) return;

	family = AF_INET;
	ret = nfct_send(nfcth,NFCT_Q_DUMP,&family);
	logmessage(LOG_INFO,appname,"nfct_send() result = %d\n",ret);
}
/*--------------------------------------------------------------------------*/
