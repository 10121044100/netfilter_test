#ifndef __NETFILTER_TEST_H__
#define __NETFILTER_TEST_H__
#include <unistd.h>

#define TRUE	1
#define FALSE	0

int32_t callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
uint32_t confirmblocking(const uint8_t* payload, const uint32_t length);
uint32_t checksites(const uint8_t* data, const uint8_t** block_list, const uint32_t length);
#endif


