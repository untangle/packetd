/**
 * nfqueue.c
 *
 * Handles receiving raw netfilter queue packets for the Untnagle Packet Daemon
 *
 * Copyright (c) 2018 Untangle, Inc.
 * All Rights Reserved
 */

#include "common.h"

#define MAX_QUEUES 128

static struct nfq_q_handle*     nfqqh[MAX_QUEUES];
static struct nfq_handle*       nfqh[MAX_QUEUES];
static int						cfg_sock_buffer = (1024 * 1024 * 4);
static int						cfg_net_maxlen = 512;
static int						cfg_net_buffer = 32768;
static int						cfg_net_queue = 2000;
static char*                    logsrc = "nfqueue";
static char*                    buffer[MAX_QUEUES];

int nfq_get_ct_info(struct nfq_data *nfad, unsigned char **data)
{
    *data = (unsigned char *)nfnl_get_pointer_to_data(nfad->data,NFQA_CT,struct nf_conntrack);
	if (*data) return NFA_PAYLOAD(nfad->data[NFQA_CT-1]);

	logmessage(LOG_DEBUG,logsrc,"Error calling nfnl_get_pointer_to_data(NFQA_CT)\n");
	return(-1);
}

unsigned int nfq_get_conntrack_id(struct nfq_data *nfad, int l3num)
{
	struct nf_conntrack		*ct;
	unsigned char			*ct_data;
	unsigned int			id;
	int						ct_len = 0;

	ct_len = nfq_get_ct_info(nfad, &ct_data);
	if (ct_len <= 0) {
        return(0);
    }

	ct = nfct_new();

	if (ct == NULL) {
		logmessage(LOG_WARNING,logsrc,"Error calling nfct_new()\n");
		return(0);
	}

	if (nfct_payload_parse((void *)ct_data,ct_len,l3num,ct ) < 0) {
		nfct_destroy(ct);
		logmessage(LOG_WARNING,logsrc,"Error calling nfq_payload_parse()\n" );
		return(0);
	}

	id = nfct_get_attr_u32(ct,ATTR_ID);
	nfct_destroy(ct);
	return(id);
}

int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data)
{
	struct nfqnl_msg_packet_hdr*    hdr;
	unsigned char*                  rawpkt;
    uint32_t                        mark;
	uint32_t    					ctid;
    uint32_t                        nfid;
	struct iphdr*                   iphead;
	int								rawlen;
    uint32_t                        family;
    intptr_t                        index = (intptr_t)data;
    char*                           buff = buffer[index];

	// get the packet header and mark
	hdr = nfq_get_msg_packet_hdr(nfad);
    if (hdr == NULL) {
		logmessage(LOG_ERR,logsrc,"NULL packet\n");
        return(0);
    }
    nfid = ntohl(hdr->packet_id);
	mark = nfq_get_nfmark(nfad);
    family = nfmsg->nfgen_family;

	// get the packet length and data
	rawlen = nfq_get_payload(nfad,(unsigned char **)&rawpkt);

	// ignore packets with invalid length
	if (rawlen < (int)sizeof(struct iphdr)) {
		nfq_set_verdict(qh,(hdr ? ntohl(hdr->packet_id) : 0),NF_ACCEPT,0,NULL);
		logmessage(LOG_WARNING,logsrc,"Invalid length %d received\n",rawlen);
		nfqueue_free_buffer(buff);
		return(0);
	}

	// use the iphdr structure for parsing
	iphead = (struct iphdr *)rawpkt;

	if (iphead->version != 4 && iphead->version != 6) {
		nfqueue_free_buffer(buff);
        return(0);
    }

	// get the conntrack ID
	if ((ctid = nfq_get_conntrack_id(nfad,family)) <= 0) {
        if (iphead->version == 4) {
            struct in_addr ip_addr;
            logmessage(LOG_DEBUG,logsrc,"Error: Failed to retrieve conntrack ID\n");
            ip_addr.s_addr = iphead->saddr;
            logmessage(LOG_DEBUG,logsrc,"Error: src IP: %s\n", inet_ntoa(ip_addr));
            ip_addr.s_addr = iphead->daddr;
            logmessage(LOG_DEBUG,logsrc,"Error: dst IP: %s\n", inet_ntoa(ip_addr));
        }
		nfqueue_set_verdict(index, nfid, NF_ACCEPT);
        nfqueue_free_buffer(buff);
        return 0;
    }

	if (get_warehouse_flag() == 'C') warehouse_capture('Q',rawpkt,rawlen,mark,ctid,nfid,family);

	if (get_bypass_flag() == 0) go_nfqueue_callback(mark,rawpkt,rawlen,ctid,nfid,family,buff,0,index);
	else nfqueue_set_verdict(index, nfid, NF_ACCEPT);

	return(0);
}

int nfqueue_set_verdict(int index, uint32_t nfid, uint32_t verdict)
{
    if (nfqqh[index] == NULL)
        return -1;

	int ret = nfq_set_verdict(nfqqh[index],nfid,verdict,0,NULL);
    if (ret < 1) {
        logmessage(LOG_ERR,logsrc,"nfq_set_verdict(): %s\n",strerror(errno));
    }

    return ret;
}

int nfqueue_startup(int index)
{
	int		ret;

	//open a new netfilter queue handler
	nfqh[index] = nfq_open();
	if (nfqh[index] == NULL) {
		logmessage(LOG_ERR,logsrc,"Error returned from nfq_open()\n");
		set_shutdown_flag();
		return(1);
	}

	// unbind any existing queue handler
	ret = nfq_unbind_pf(nfqh[index],AF_INET);
	if (ret < 0) {
		logmessage(LOG_ERR,logsrc,"Error returned from nfq_unbind_pf()\n");
		set_shutdown_flag();
		return(2);
	}

	// bind the queue handler for AF_INET
	ret = nfq_bind_pf(nfqh[index],AF_INET);
	if (ret < 0) {
		logmessage(LOG_ERR,logsrc,"Error returned from nfq_bind_pf(lan)\n");
		set_shutdown_flag();
		return(3);
	}

	// create a new netfilter queue
	nfqqh[index] = nfq_create_queue(nfqh[index],cfg_net_queue+index,netq_callback,(void*)(intptr_t)index);
	if (nfqqh[index] == 0) {
		logmessage(LOG_ERR,logsrc,"Error returned from nfq_create_queue(%u)\n",cfg_net_queue);
		set_shutdown_flag();
		return(4);
	}

	// set the queue length
	ret = nfq_set_queue_maxlen(nfqqh[index],cfg_net_maxlen);
	if (ret < 0) {
		logmessage(LOG_ERR,logsrc,"Error returned from nfq_set_queue_maxlen(%d)\n",cfg_net_maxlen);
		set_shutdown_flag();
		return(5);
	}

	// set the queue data copy mode
	ret = nfq_set_mode(nfqqh[index],NFQNL_COPY_PACKET,cfg_net_buffer);
	if (ret < 0) {
		logmessage(LOG_ERR,logsrc,"Error returned from nfq_set_mode(NFQNL_COPY_PACKET)\n");
		set_shutdown_flag();
		return(6);
	}

	// set flag so we also get the conntrack info for each packet
	ret = nfq_set_queue_flags(nfqqh[index],NFQA_CFG_F_FAIL_OPEN,NFQA_CFG_F_FAIL_OPEN);
	if (ret < 0) {
		logmessage(LOG_ERR,logsrc,"Error returned from nfq_set_queue_flags(NFQA_CFG_F_FAIL_OPEN)\n");
		set_shutdown_flag();
		return(7);
	}

	// set flag so we also get the conntrack info for each packet
	ret = nfq_set_queue_flags(nfqqh[index],NFQA_CFG_F_CONNTRACK,NFQA_CFG_F_CONNTRACK);
	if (ret < 0) {
		logmessage(LOG_ERR,logsrc,"Error returned from nfq_set_queue_flags(NFQA_CFG_F_CONNTRACK)\n");
		set_shutdown_flag();
		return(8);
	}

	return(0);
}

void nfqueue_shutdown(int index)
{
    struct nfq_q_handle* qh = nfqqh[index];
    struct nfq_handle* h = nfqh[index];

    nfqqh[index] = NULL;
    nfqh[index] = NULL;

    // destroy the netfilter queue
    if (qh != NULL)
        nfq_destroy_queue(qh);

	// shut down the netfilter queue handler
    if (h != NULL)
        nfq_close(h);
}

int nfqueue_thread(int index)
{
	struct pollfd	network;
	int				netsock;
	int				val,ret;

	logmessage(LOG_INFO,logsrc,"The nfqueue thread [%i] is starting\n", index);

	ret = nfqueue_startup(index);

	if (ret != 0) {
		logmessage(LOG_ERR,logsrc,"Error %d returned from nfqueue_startup()\n",ret);
		set_shutdown_flag();
		return(1);
	}

	// set the socket receive buffer size
	ret = nfnl_rcvbufsiz(nfq_nfnlh(nfqh[index]),cfg_sock_buffer);

	// get the socket descriptor for the netlink queue
	netsock = nfnl_fd(nfq_nfnlh(nfqh[index]));

	// set up the network poll structure
	network.fd = netsock;
	network.events = POLLIN;
	network.revents = 0;

	go_child_startup();

	while (get_shutdown_flag() == 0) {
		// wait for data on the socket
		ret = poll(&network,1,1000);

		// nothing received so just continue
		if (ret == 0) {
            continue;
        }

		// handle poll errors
		if (ret < 0) {
			if (errno == EINTR) {
				logmessage(LOG_ALERT,logsrc,"Detected EINTR waiting for messages\n");
				continue;
			}
			logmessage(LOG_ERR,logsrc,"Error %d (%s) returned from poll()\n",errno,strerror(errno));
			break;
		}

		// allocate a buffer to hold the packet
		buffer[index] = (char *)malloc(cfg_net_buffer);

		if (buffer[index] == NULL) {
			logmessage(LOG_ERR,logsrc,"Unable to allocate memory for packet\n");
			set_shutdown_flag();
			break;
		}

        // read from the nfqueue socket
        ret = recv(netsock,buffer[index],cfg_net_buffer,MSG_DONTWAIT);

        if (ret == 0) {
            logmessage(LOG_ERR,logsrc,"The nfqueue socket was unexpectedly closed\n");
			nfqueue_free_buffer(buffer[index]);
			set_shutdown_flag();
            break;
        }

        if (ret < 0) {
			if ((errno == EAGAIN) || (errno == EINTR) || (errno == ENOBUFS)) {
				logmessage(LOG_WARNING,logsrc,"Detected error %d (%s) while calling recv()\n",errno,strerror(errno));
				continue;
			}
            logmessage(LOG_ERR,logsrc,"Error %d (%s) returned from recv()\n",errno,strerror(errno));
			nfqueue_free_buffer(buffer[index]);
			set_shutdown_flag();
            break;
        }

        // pass the data to the packet handler
        nfq_handle_packet(nfqh[index],buffer[index],ret);
	}

	// call our nfqueue shutdown function
	nfqueue_shutdown(index);

	logmessage(LOG_INFO,logsrc,"The nfqueue thread [%i] has terminated\n", index);
	go_child_shutdown();
	return(0);
}

void nfqueue_free_buffer(char *buffer)
{
	if (!buffer)
		logmessage(LOG_ERR,logsrc,"nfqueue_free_buffer call with NULL\n");
	else
		free(buffer);
}
