#ifndef NFQNL_THREAD_H 
#define NFQNL_THREAD_H

#include "nfct.h"

int get_app_data_offset(const unsigned char *data);
int get_conn_key_of_packet(const unsigned char *data,char * buf, enum reverse flag);


u_int32_t handle_packet(struct nfq_data * tb,
                        struct nfq_q_handle *qh,
                        struct conntrack * connt);
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data);
void nfq_start(void * pconnt);


#endif
