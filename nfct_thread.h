#ifndef NFCT_THREAD_H
#define NFCT_THREAD_H 
#include "nfct.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>


void nfct_start(void * pconnt);
static int event_cb(enum nf_conntrack_msg_type , struct nf_conntrack, void *);
#endif 

