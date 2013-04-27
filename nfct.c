#include "stdxh.h"
#include "nfct.h"
#include "identify.h"

//link list related functions
//
//
//Allocate and init struct connection ;
struct connection *  new_connection(){
    struct connection * c;
    int i;
    c = (struct connection *) malloc(sizeof(struct connection));

    if(c ==NULL) return NULL;

    pthread_mutex_init(&c->mutex_num_packet,NULL);
    pthread_mutex_init(&c->mutex_buffer,NULL);
    c->lengthsofar = 0;
    c->num_packet = 0;
    c->mark = UNTOUCHED;
    c->next =NULL;
    for (i=0;i<CONNECTION_KEY_LEN;++i){
        c->key[i] = '\0';
    }
    for (i=0;i<CONNECTION_BUFF_LEN;++i){
        c->buffer[i] = '\0'; 
    }
    return c;
}

struct conntrack * new_conntrack(){
    struct conntrack * c;
    c = (struct conntrack *) malloc (sizeof (struct conntrack));
    if(c == NULL) return c;
/*
    c->cth = nfct_open(CONNTRACK , NFCT_ALL_CT_GROUPS);
    if(!cth){
        perror("Can't open Netfilter connection tracking handler, Are u root?\n")
        exit(1);
    }
    */

    c->conn_list = NULL;
    c->queuenum = 0 ;
    //new identifier
    c->iden_num = new_identifiter("./pro.config",&c->iden_array);
    return c ;
}

int make_key(struct nf_conntrack * ct, char * key,enum reverse flag){
    struct nfct_attr_grp_ipv4 nfct_ipv4;
    struct nfct_attr_grp_port nfct_port;
    u_int8_t  protonum;
    u_int16_t port;
    if(key == NULL) return 1;
    if(flag == true){
        nfct_get_attr_grp(ct,ATTR_GRP_ORIG_IPV4,&nfct_ipv4);
        nfct_get_attr_grp(ct,ATTR_GRP_ORIG_PORT,&nfct_port);
    }
    else{
        nfct_get_attr_grp(ct,ATTR_GRP_REPL_IPV4,&nfct_ipv4);
        nfct_get_attr_grp(ct,ATTR_GRP_REPL_PORT,&nfct_port);
    }
    protonum = nfct_get_attr_u8(ct,ATTR_L4PROTO);
    
    //should use snprintf
    if(sprintf(key,"%u:%d.%d.%d.%d:%d.%d.%d.%d:%hu:%hu\0",protonum, \
             nfct_ipv4.src <<24 >> 24, nfct_ipv4.src << 16 >>24,\
             nfct_ipv4.src << 8 >> 24, nfct_ipv4.src >> 24 ,\
             nfct_ipv4.dst << 24>> 24, nfct_ipv4.dst << 16 >>24 ,\
             nfct_ipv4.dst << 8 >> 24, nfct_ipv4.dst >> 24,\
             ntohs(nfct_port.sport), ntohs(nfct_port.dport)) 
             > CONNECTION_KEY_LEN){
        perror("Make Key overflowed!\n");
        exit(1);
    }
    return 0;
}


int increase_pkt_num(struct connection * conn_node){
    pthread_mutex_lock(&conn_node->mutex_num_packet);
    ++conn_node->num_packet;
    pthread_mutex_unlock(&conn_node->mutex_num_packet);
}

int append_to_buffer(struct connection * conn_node, 
                     char * app_data, unsigned int appdatalen){
    unsigned int i,length = 0, oldlength = conn_node->lengthsofar;
    pthread_mutex_lock(&conn_node->mutex_buffer);
    for ( i = 0; i < (CONNECTION_BUFF_LEN - conn_node->lengthsofar)  \
                              && i < appdatalen; ++i){
        if(app_data[i] != '\0'){
            conn_node->buffer[length + oldlength] = app_data[i];
            ++length;
        } 
    }
    conn_node->buffer[length + oldlength] = '\0';
    conn_node->lengthsofar += length;

    pthread_mutex_unlock(&conn_node->mutex_buffer);
    
}

//append a connection in the tail of the conn_list 
int append_connection(struct conntrack *connt,struct connection *conn_node){
    struct connection * p = connt->conn_list;

    if(connt ==NULL || conn_node == NULL){
        return -1;
    }

    if(p == NULL){
        connt->conn_list = conn_node ; 
        return 0;
    }

    while(p->next != NULL){
        p = p->next;
    }
    p->next = conn_node;
    return 0;
}


//insert a connection in the head of the conn_list
int insert_connection(struct conntrack * connt , 
                      struct connection *conn_node
                      ){
    if(connt == NULL || conn_node == NULL){
        return -1 ; 
    }
    conn_node->next = connt->conn_list;
    connt->conn_list = conn_node;
    return 0;
}


//Delete a connection by key value , 0 for success, non-0 for error
int del_connection(struct conntrack * connt, char * key){
    struct connection *p =connt->conn_list , *q =p;
    if(connt == NULL || key ==NULL ||connt->conn_list ==NULL){
        return -1; 
    }
    while(p != NULL){
        if(strcmp(key, p->key)==0){
            break;
        }
        q = p ;
        p = p->next;
    } 
    if(p ==NULL){
        //not found 
        return -1 ;
    }
    else if(p == q) {
            connt->conn_list = p->next;
            free(p);
        }
        else{
            q->next = p->next;
            free(p);
        }
    return 0;
}

struct connection * get_connection(struct conntrack * connt, char * key){
    struct connection * p ;
    if(connt == NULL || key ==NULL) return NULL;
    p = connt->conn_list;
    while(p != NULL){
        if(strcmp(p->key , key) == 0) 
            break;
        p = p->next; 
    }
    if(p == NULL) 
        return NULL;
    else     
        return p;
}
//
//
//
//end of link list related  funtions
//
/*
int main(){
    struct conntrack * connt;
    struct connection * connect;
    char * key  ; 
    key = (char *)malloc (sizeof(char));
    key[0] = '\0';
    connt = new_conntrack();

    connect = new_connection();
    insert_connection(connt , connect);
    connect = new_connection();
    insert_connection(connt , connect);
    connect = new_connection();
    insert_connection(connt , connect);
    del_connection(connt ,key );

    nfct_callback_register(); 

    return 0 ;
}
*/
