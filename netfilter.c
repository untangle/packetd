/**
 * netfilter.c
 *
 * Handles receiving raw netfilter packets for the Untnagle Packet Daemon
 *
 * Copyright (c) 2018 Untangle, Inc.
 * All Rights Reserved
 */

#include "common.h"
/*--------------------------------------------------------------------------*/
static struct nfq_q_handle		*nfqqh;
static struct nfq_handle		*nfqh;
static int						cfg_sock_buffer = 1048576;
static int						cfg_net_maxlen = 10240;
static int						cfg_net_buffer = 32768;
static int						cfg_net_queue = 1818;
static char                     *appname = "netfilter";
/*--------------------------------------------------------------------------*/
int nfq_get_ct_info(struct nfq_data *nfad, unsigned char **data)
{
	*data = (unsigned char *)nfnl_get_pointer_to_data(nfad->data,NFQA_CT,struct nf_conntrack);
	if (*data) return NFA_PAYLOAD(nfad->data[NFQA_CT-1]);

	logmessage(LOG_WARNING,appname,"Error calling nfnl_get_pointer_to_data(NFQA_CT)\n");
	return(-1);
}
/*--------------------------------------------------------------------------*/
unsigned int nfq_get_conntrack_id(struct nfq_data *nfad, int l3num)
{
	struct nf_conntrack		*ct;
	unsigned char			*ct_data;
	unsigned int			id;
	int						ct_len = 0;

	ct_len = nfq_get_ct_info(nfad, &ct_data);
	if (ct_len <= 0) return(0);

	ct = nfct_new();

	if (ct == NULL) {
		logmessage(LOG_WARNING,appname,"Error calling nfct_new()\n");
		return(0);
	}

	if (nfct_payload_parse((void *)ct_data,ct_len,l3num,ct ) < 0) {
		nfct_destroy(ct);
		logmessage(LOG_WARNING,appname,"Error calling nfq_payload_parse()\n" );
		return(0);
	}

	id = nfct_get_attr_u32(ct,ATTR_ID);
	nfct_destroy(ct);
	return(id);
}
/*--------------------------------------------------------------------------*/
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data)
{
	struct nfqnl_msg_packet_hdr		*hdr;
	unsigned char					*rawpkt;
    unsigned int                    omark,nmark;
	unsigned int					ctid;
	struct iphdr					*iphead;
	int								rawlen;

	// get the packet header and mark
	hdr = nfq_get_msg_packet_hdr(nfad);
	omark = nfq_get_nfmark(nfad);

	// get the packet length and data
	rawlen = nfq_get_payload(nfad,(unsigned char **)&rawpkt);

	// ignore packets with invalid length
	if (rawlen < (int)sizeof(struct iphdr)) {
		nfq_set_verdict(qh,(hdr ? ntohl(hdr->packet_id) : 0),NF_ACCEPT,0,NULL);
		logmessage(LOG_WARNING,appname,"Invalid length %d received\n",rawlen);
		return(0);
	}

	// use the iphdr structure for parsing
	iphead = (struct iphdr *)rawpkt;

	// ignore everything except IPv4
	if (iphead->version != 4) return(0);

	// we only care about TCP and UDP
	if ((iphead->protocol != IPPROTO_TCP) && (iphead->protocol != IPPROTO_UDP))	return(0);

	// get the conntrack ID
	ctid = nfq_get_conntrack_id(nfad,nfmsg->nfgen_family);

	// call the go handler function
	nmark = go_netfilter_callback(omark,rawpkt,rawlen,ctid);

	// set the verdict and the returned mark
	nfq_set_verdict2(qh,(hdr ? ntohl(hdr->packet_id) : 0),NF_ACCEPT,nmark,0,NULL);

	return(0);
}
/*--------------------------------------------------------------------------*/
int netfilter_startup(void)
{
	int		ret;

	//open a new netfilter queue handler
	nfqh = nfq_open();

	if (nfqh == NULL) {
		logmessage(LOG_ERR,appname,"Error returned from nfq_open()\n");
		set_shutdown_flag(1);
		return(1);
	}

	// unbind any existing queue handler
	ret = nfq_unbind_pf(nfqh,AF_INET);

	if (ret < 0) {
		logmessage(LOG_ERR,appname,"Error returned from nfq_unbind_pf()\n");
		set_shutdown_flag(1);
		return(2);
	}

	// bind the queue handler for AF_INET
	ret = nfq_bind_pf(nfqh,AF_INET);

	if (ret < 0) {
		logmessage(LOG_ERR,appname,"Error returned from nfq_bind_pf(lan)\n");
		set_shutdown_flag(1);
		return(3);
	}

	// create a new netfilter queue
	nfqqh = nfq_create_queue(nfqh,cfg_net_queue,netq_callback,NULL);

	if (nfqqh == 0) {
		logmessage(LOG_ERR,appname,"Error returned from nfq_create_queue(%u)\n",cfg_net_queue);
		set_shutdown_flag(1);
		return(4);
	}

	// set the queue length
	ret = nfq_set_queue_maxlen(nfqqh,cfg_net_maxlen);

	if (ret < 0) {
		logmessage(LOG_ERR,appname,"Error returned from nfq_set_queue_maxlen(%d)\n",cfg_net_maxlen);
		set_shutdown_flag(1);
		return(5);
	}

	// set the queue data copy mode
	ret = nfq_set_mode(nfqqh,NFQNL_COPY_PACKET,cfg_net_buffer);

	if (ret < 0) {
		logmessage(LOG_ERR,appname,"Error returned from nfq_set_mode(NFQNL_COPY_PACKET)\n");
		set_shutdown_flag(1);
		return(6);
	}

	// set flag so we also get the conntrack info for each packet
	ret = nfq_set_queue_flags(nfqqh,NFQA_CFG_F_CONNTRACK,NFQA_CFG_F_CONNTRACK);

	if (ret < 0) {
		logmessage(LOG_ERR,appname,"Error returned from nfq_set_queue_flags(NFQA_CFG_F_CONNTRACK)\n");
		set_shutdown_flag(1);
		return(7);
	}

	return(0);
}
/*--------------------------------------------------------------------------*/
void netfilter_shutdown(void)
{
	// destroy the netfilter queue
	nfq_destroy_queue(nfqqh);

	// shut down the netfilter queue handler
	nfq_close(nfqh);
}
/*--------------------------------------------------------------------------*/
int netfilter_thread(void)
{
	struct pollfd	network;
	char			*buffer;
	int				netsock;
	int				val,ret;

	logmessage(LOG_INFO,appname,"The netfilter thread is starting\n");

	// allocate our packet buffer
	buffer = (char *)malloc(cfg_net_buffer);

	// call our netfilter startup function
	ret = netfilter_startup();

	if (ret != 0) {
		logmessage(LOG_ERR,appname,"Error %d returned from netfilter_startup()\n",ret);
		set_shutdown_flag(1);
		return(1);
	}

	// get the socket descriptor for the netlink queue
	netsock = nfnl_fd(nfq_nfnlh(nfqh));

	// set the socket receive buffer size if config value is not zero
	if (cfg_sock_buffer != 0) {
		val = cfg_sock_buffer;
		ret = setsockopt(netsock,SOL_SOCKET,SO_RCVBUF,&val,sizeof(val));

		if (ret != 0) {
			logmessage(LOG_ERR,appname,"Error %d returned from setsockopt(SO_RCVBUF)\n",errno);
			set_shutdown_flag(1);
			return(1);
		}
	}

	// set up the network poll structure
	network.fd = netsock;
	network.events = POLLIN;
	network.revents = 0;

	go_child_startup();

	while (get_shutdown_flag() == 0) {
		// wait for data on the socket
		ret = poll(&network,1,1000);

		// nothing received so just continue
		if (ret == 0) continue;

		// handle poll errors
		if (ret < 0) {
			if (errno == EINTR)	continue;
			logmessage(LOG_ERR,appname,"Error %d (%s) returned from poll()\n",errno,strerror(errno));
			break;
		}

		do {
			// read from the netfilter socket
			ret = recv(netsock,buffer,cfg_net_buffer,MSG_DONTWAIT);

			if (ret == 0) {
				logmessage(LOG_ERR,appname,"The netfilter socket was unexpectedly closed\n");
				set_shutdown_flag(1);
				break;
			}

			if (ret < 0) {
				if ((errno == EAGAIN) || (errno == EINTR) || (errno == ENOBUFS)) break;
				logmessage(LOG_ERR,appname,"Error %d (%s) returned from recv()\n",errno,strerror(errno));
				set_shutdown_flag(1);
				break;
			}

			// pass the data to the packet handler
			nfq_handle_packet(nfqh,buffer,ret);
		} while (ret > 0);
	}

	// call our netfilter shutdown function
	netfilter_shutdown();

	// free our packet buffer memory
	free(buffer);

	logmessage(LOG_INFO,appname,"The netfilter thread has terminated\n");
	go_child_goodbye();
	return(0);
}
/*--------------------------------------------------------------------------*/
void netfilter_goodbye(void)
{
	set_shutdown_flag(1);
}
/*--------------------------------------------------------------------------*/
