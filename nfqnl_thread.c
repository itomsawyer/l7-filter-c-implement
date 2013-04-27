#include "stdxh.h"

#include "nfct.h"
#include "identify.h"

int maxpackets = 10 ;
int clobbermark = 0;

//mask used for identify.h
extern unsigned int markmask;
extern unsigned int maskfirstbit;
extern unsigned int masknbits;


u_int32_t handle_packet(struct nfq_data * tb,
                        struct nfq_q_handle*qh,
                        struct conntrack * connt){
   int id = 0 , ret , dataoffset , datalen;
   u_int32_t wholemark , mark , ifi;
   struct nfqnl_msg_packet_hdr *ph;
   char * data , key[CONNECTION_KEY_LEN];
   struct connection * pconnection;
   //conntrack here !!!!!!!!
   //
   ph = nfq_get_msg_packet_hdr(tb);
   if(ph){ 
       id = ntohl(ph->packet_id);
       //print 
   }

  // Need to get the wholemark so that we can pass the unmasked part back
  // Except for the print statement and debugging, there's not really any
  // reason to pull out the masked part, because it's always modified without
  // looking at it...
  
   wholemark = (nfq_get_nfmark(tb));
   if(clobbermark){  
       mark = UNTOUCHED;
       wholemark = wholemark & (~markmask);
   }
   else{
       ((wholemark & markmask) >> maskfirstbit);
   }

   ret = nfq_get_payload(tb,&data);
   if(ret < 0 ){
       fprintf(stderr,"Cannot get payload!\n");
   }
  //packet data detect above layer 3 , let's do it ! 
   char ip_protocol = data[9];

  //Ignore non-TCP or non-UDP packets
   if(ip_protocol != IPPROTO_TCP && ip_protocol != IPPROTO_UDP){ 
       return nfq_set_verdict(qh , id , NF_ACCEPT , 0 ,NULL);
   }
   dataoffset = get_app_data_offset((const unsigned char *) data);
   datalen = ret -dataoffset ;
/*
   if( classify(connt->iden_array,connt->iden_num,data + dataoffset) != NO_MATCH_YET){        
       printf("%s\n",data + dataoffset);
   }
*/
   get_conn_key_of_packet((const unsigned char *)data,key,false);
   pconnection = get_connection(connt,key);
   if(pconnection == NULL){
       //check the conntrack backwards
        get_conn_key_of_packet((const unsigned char *)data,key,true); 
        pconnection = get_connection(connt,key);
   }
   if(pconnection != NULL){
          increase_pkt_num(pconnection);    
          if(datalen <= 0){
                mark=NO_MATCH_YET;//no application data , ignored 
          }
          else{
            if(pconnection->mark!=UNTOUCHED && pconnection->mark!=NO_MATCH_YET)
            {//It is classified already . Reapply existing mark
                mark = pconnection->mark;
            }
            else if (pconnection->num_packet <= maxpackets){
                    append_to_buffer(pconnection,(char*)(data+dataoffset), \
                                 ret-dataoffset);
                    mark = classify(connt->iden_array, \
                                connt->iden_num, \
                                pconnection->buffer);
                    if(mark != NO_MATCH_YET){// classify sucessful!!!
                        printf("%s has been classified as %d\n", \
                        pconnection->key,mark);
                      //  free(pconnection->buffer);
                       // pconnection->buffer = NULL;
                    }
                    pconnection->mark = mark;
                }
                else{ //num_packet > maxpackets  , give up classification
                    mark = NO_MATCH;
                    /*
                    if(pconnection->num_packet == maxpackets+1){
                        //printf give up message
                        free(pconnection->buffer);
                        pconnection->buffer = NULL;
                    }//should clean up
                    */
                }//give up classification
          }//datalen > 0 
          pconnection->mark = mark;
   }//connection is found


   return nfq_set_verdict_mark(qh, id, NF_ACCEPT, \
                              htonl((mark<<maskfirstbit)|wholemark), 0, NULL);
}

int  get_conn_key_of_packet(const unsigned char *data,char * buf, enum reverse flag){
    int ip_hl = 4*(data[0] & 0x0f), ret;
    u_int8_t ip_protocol = data[9];
    
    if(ip_protocol == IPPROTO_TCP){
        if(flag){
          ret=sprintf(buf,"%u:%d.%d.%d.%d:%d.%d.%d.%d:%hu:%hu\0",ip_protocol,\
	      data[12], data[13], data[14], data[15],  \
	      data[16], data[17], data[18], data[19],  \
	      data[ip_hl]*256+data[ip_hl+1], data[ip_hl+2]*256+data[ip_hl+3]);
        } 
        else{
          ret=sprintf(buf,"%u:%d.%d.%d.%d:%d.%d.%d.%d:%hu:%hu\0",ip_protocol,\
	      data[16], data[17], data[18], data[19], \
	      data[12], data[13], data[14], data[15], \
	      data[ip_hl+2]*256+data[ip_hl+3], data[ip_hl]*256+data[ip_hl+1]);
        }
    }
    else if (ip_protocol == IPPROTO_UDP){
        if(flag){
          ret=sprintf(buf,"%u:%d.%d.%d.%d:%d.%d.%d.%d:%hu:%hu\0",ip_protocol,\
	      data[12], data[13], data[14], data[15], \
	      data[16], data[17], data[18], data[19], \
	      data[ip_hl]*256+data[ip_hl+1], data[ip_hl+2]*256+data[ip_hl+3]);
        }
        else{
          ret=sprintf(buf,"%u:%d.%d.%d.%d:%d.%d.%d.%d:%hu:%hu\0",ip_protocol,\
	      data[16], data[17], data[18], data[19], \
	      data[12], data[14], data[14], data[15], \
	      data[ip_hl+2]*256+data[ip_hl+3], data[ip_hl]*256+data[ip_hl+1]);
        }
    }
    if (ret < CONNECTION_KEY_LEN) return 0 ;
    else{
        perror ("Get connection key of packet overflowed!\n");
        exit(1);
    }
}


/* Returns offset the into the skb->data that the application data starts */
int get_app_data_offset(const unsigned char *data)
{
  int ip_hl = 4*(data[0] & 0x0f);
  char ip_protocol = data[9];

  if(ip_protocol == IPPROTO_TCP){
    // 12 == offset into TCP header for the header length field.
    int tcp_hl = 4*(data[ip_hl + 12]>>4);
    return ip_hl + tcp_hl;
  }
  else if(ip_protocol == IPPROTO_UDP){
    return ip_hl + 8; /* UDP header is always 8 bytes */
  }
  else{
      fprintf(stderr, "Tried to get app data offset for unsupported protocol!\n");
      return ip_hl + 8; /* something reasonable */
  }
}



static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
        //u_int32_t id = print_pkt(nfa);
        struct conntrack * connt = (struct conntrack *)data;
        struct nfqnl_msg_packet_hdr *ph;
        u_int32_t id = 0;

        ph = nfq_get_msg_packet_hdr(nfa);
        if(ph){
            id = ntohl(ph->packet_id); 
        }
        else{
            fprintf(stderr,"Cannot get packet header!\n");
        }

        u_int32_t wholemark = nfq_get_nfmark(nfa);
        printf("Callback!\n");

        
  // If it already has a mark (and we don't want to clobber it), 
  // just pass it back with the same mark
        if((wholemark<<maskfirstbit)&markmask != UNTOUCHED && !clobbermark){
            static unsigned int naaltered = 0;
            naaltered++;
            if((naaltered^(naaltered-1)) == (2*naaltered -1))
                fprintf(stderr,"Warning:Receive already altered packets\n");
            return nfq_set_verdict_mark(qh , id , NF_ACCEPT , htonl(wholemark),0,NULL);
        }

        //identify the packets here!!!!!!!!!!!! 
        
        //printf("entering callback\n");
        //return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        return handle_packet(nfa,qh,connt);
}
//parameter should have point to conntrack!!!!!!!!!!!!!!!
void nfq_start(void * pconnt)
{
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        struct nfnl_handle *nh;
        struct conntrack * connt = (struct conntrack *) pconnt;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));

        printf("opening library handle\n");
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "error during nfq_open()\n");
                exit(1);
        }

        printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_unbind_pf()\n");
                exit(1);
        }

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
        if (nfq_bind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_bind_pf()\n");
                exit(1);
        }

        printf("binding this socket to queue  %d\n",connt->queuenum);
        /////NULL should be conntrack !!!!!!!!!!!!!!!!1
        qh = nfq_create_queue(h, connt->queuenum , &cb, connt);
        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

        printf("setting copy_packet mode\n");
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                exit(1);
        }

        fd = nfq_fd(h);

        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                nfq_handle_packet(h, buf, rv);
        }

        printf("unbinding from queue 0\n");
        nfq_destroy_queue(qh);

#ifdef INSANE
        /* normally, applications SHOULD NOT issue this command, since
         * it detaches other programs/sockets from AF_INET, too ! */
        printf("unbinding from AF_INET\n");
        nfq_unbind_pf(h, AF_INET);
#endif

        printf("closing library handle\n");
        nfq_close(h);

        exit(0);
}


