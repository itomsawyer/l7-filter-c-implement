#ifndef NFCT_H
#define NFCT_H
#include <pthread.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "identify.h"

#define CONNECTION_KEY_LEN 128
#define CONNECTION_BUFF_LEN (8*1500)

enum reverse{false=0,true=1};

struct connection{
    char key[CONNECTION_KEY_LEN];
    unsigned int num_packet;
    unsigned int mark;
    pthread_mutex_t mutex_num_packet;
    pthread_mutex_t mutex_buffer;
    char  buffer[CONNECTION_BUFF_LEN];
    unsigned int lengthsofar;
    struct connection * next; 
};


struct conntrack{
    struct nfct_conntrack *ct ;
    struct nfct_handle *cth;
    int queuenum;
    int iden_num;
    struct identifier *iden_array;
    struct connection *conn_list;
};

struct connection *  new_connection();
struct conntrack * new_conntrack();
int  make_key(struct nf_conntrack * ct,char * key,enum reverse); 
int increase_pkt_num(struct connection * conn_node);
int append_to_buffer(struct connection * conn_node, 
                     char *app_data, unsigned int appdatalen);
int append_connection(struct conntrack *connt,struct connection *conn_node);
int insert_connection(struct conntrack * connt ,
                      struct connection *conn_node);
int del_connection(struct conntrack * connt, char * key);
struct connection * get_connection(struct conntrack *connt,char *key);

#endif
