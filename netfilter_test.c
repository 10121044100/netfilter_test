#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include "netfilter_test.h"

#include <dumpcode.h>

/*
 *	confirmblocking
 *	specific sites confirm.
 *	if site is included specific sites, return true(1).
 */
#define IPHDRLEN(x)	(((struct iphdr*)x)->ihl * 4)
#define TCPHDRLEN(x)	(((struct tcphdr*)x)->th_off * 4)
#define PORT_HTTP	80

uint32_t 
confirmblocking(
	uint8_t*	payload, 
	uint32_t 	length) 
{
	struct iphdr	*ipptr = (struct iphdr *) payload;
	struct tcphdr	*tcpptr = (struct tcphdr *) (payload + IPHDRLEN(ipptr));
	uint8_t		*data = NULL;
	uint32_t	data_length = 0;

	// Check TCP from ipptr	
	if(ipptr->protocol == IPPROTO_TCP) {
		if(tcpptr->th_dport == htons(PORT_HTTP)) {
			data = (uint8_t*) (tcpptr + TCPHDRLEN(tcpptr));
			data_length = length - IPHDRLEN(ipptr) - TCPHDRLEN(tcpptr);

			dumpcode(data, data_length);

			return TRUE;
		}
	}

	return FALSE;
}


/*
 *	callback
 *	This function receive a packet from netfilter_queue,
 *	And prevent specific sites.
 */
int32_t 
callback(
	struct nfq_q_handle 	*qh, 
	struct nfgenmsg 	*nfmsg,
	struct nfq_data 	*nfa, 
	void			*data)
{
	u_int32_t id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	u_int32_t payload_length;
	unsigned char *payload;
	u_int32_t isblocksite = 0;	// True & false

	printf("entering callback\n");
	
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}
	
	payload_length = nfq_get_payload(nfa, &payload);
	//if (payload_length >= 0)	// Always True
	printf("payload_len=%d ", payload_length);
	fputc('\n', stdout);
	dumpcode(data, payload_length);

	isblocksite = confirmblocking(payload, payload_length);

	if(isblocksite)
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

