#include "stdxh.h"
#include "nfct.h"



static int event_cb(enum nf_conntrack_msg_type type, 
                    struct nf_conntrack *ct , 
                    void * data){
    struct conntrack * ct_status = (struct conntrack *) data;
    char  key[CONNECTION_KEY_LEN]= "\0";
//    struct nfct_attr_grp_ipv4  nfct_ipv4; 
//    struct nfct_attr_grp_port  nfct_port; 
    u_int8_t proto;


    proto = nfct_get_attr_u8(ct ,ATTR_L4PROTO);
    //We only focus on UDP and TCP packets !!!!!!!!!!!!
    if(proto!= IPPROTO_UDP && proto!= IPPROTO_TCP) return NFCT_CB_CONTINUE;

   // printf("%c src=%d dst=%d \n",&proto,nfct_ipv4.src,nfct_ipv4.dst);
    if(type == NFCT_T_NEW){
        make_key(ct,key,false);
        if(get_connection(ct_status,key) == NULL){
            make_key(ct, key,true); 
            if(get_connection(ct_status,key) != NULL){
                fprintf(stderr,"Connetion is already existed!\n");
                return NFCT_CB_CONTINUE;
            } 
        }
        else{
            fprintf(stderr,"Connetion is already existed!\n");
            return NFCT_CB_CONTINUE;
        }
        
        
        struct connection * conn_node;

        if((conn_node = new_connection()) == NULL){
            fprintf(stderr,"Create new connection error!\n"); 
            return NFCT_CB_FAILURE;
        }
        strcpy(conn_node->key,key);
        if(insert_connection(ct_status,conn_node) == 0){
            printf("Find new connection %s\n",conn_node->key);
        }
        else{
            fprintf(stderr,"Insert new connection error!\n"); 
            return NFCT_CB_FAILURE;
        }
    }
    else if(type == NFCT_T_DESTROY){
        make_key(ct,key,true);
        if(del_connection(ct_status,key) == 0 ){
            printf("Destroyed connection %s\n",key);
        }   
        else {
            make_key(ct,key,false);
            if(del_connection(ct_status,key) ==0){
                printf("Destroyed connection %s\n",key);
            }
            else{
                fprintf(stderr,"No connection to be destroy!\n");
            }
        }

        return NFCT_CB_CONTINUE;

    }
    return NFCT_CB_CONTINUE;
} 
    
void nfct_start(void * pconnt){
    int ret;
    struct nfct_handle *h;
    struct conntrack * connt = (struct conntrack *) pconnt;
    h = nfct_open(CONNTRACK , NFCT_ALL_CT_GROUPS);
                            
    if(!h){
        fprintf(stderr, "nfct_open failed\n");
        exit(1);
    }
    
    nfct_callback_register(h, NFCT_T_ALL, event_cb ,connt );


    ret = nfct_catch(h);
    //make a dead loop here , but NOT should be 
    while (1){;}
    nfct_close(h);
}

