#include "stdxh.h"
#include "nfct.h"
#include "nfqnl_thread.h"
#include "nfct_thread.h"


//extern void nfq_start(void * pconnt);

//extern struct conntrack * new_conntrack();


int main(int argc ,char * argv []){
    pthread_t nfq_pthread;
    pthread_t nfct_pthread;
    int ret;
    struct conntrack * connt;

    connt = new_conntrack();
    if(connt ==NULL){
        fprintf(stderr, "New conntrack error!\n");
        exit(1);
    }
    if(argc == 1){
        connt->queuenum = atoi(*argv);
    }
    
    //should have queue num and conntrack struct 
    ret = pthread_create(&nfq_pthread, NULL,(void *)nfq_start,connt);
    if(ret!= 0){
        perror("Create nfq_pthread error\n");
        exit(1);
    }
    ret = pthread_create(&nfct_pthread,NULL,(void *)nfct_start,connt);
    if(ret!= 0){
        perror("Create nfct_pthread error\n");
        exit(1);
    }
    pthread_join(nfct_pthread,NULL);
    pthread_join(nfq_pthread,NULL);
    while(1){
        sleep(5000);
        printf("running\n");
    };
    return 0 ;
}

