#ifndef __NETFILTER_TEST_H__
#define __NETFILTER_TEST_H__
#include <unistd.h>

#define TRUE	1
#define FALSE	0

int32_t callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
uint32_t confirmblocking(unsigned char* payload, uint32_t length);
#endif


