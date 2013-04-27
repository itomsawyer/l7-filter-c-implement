CC = gcc 
CFLAGS = -g #-Wall
LIBS = -lnfnetlink -lnetfilter_queue -lnetfilter_conntrack -lpthread
OBJS:= main.o nfqnl_thread.o  identify.o nfct.o nfct_thread.o
all: filter 
filter: $(OBJS) 
	$(CC) $(CFLAGS) -o filter $(LIBS) $(OBJS)
main.o: main.c 
	$(CC) $(CFLAGS) -o main.o -c main.c 
nfqnl_thread.o: nfqnl_thread.c  
	$(CC) $(CFLAGS) -o nfqnl_thread.o -c nfqnl_thread.c 
nfct_thread.o: nfct_thread.c
	$(CC) $(CFLAGS) -o nfct_thread.o -c nfct_thread.c
identify.o: identify.c
	$(CC) $(CFLAGS) -o identify.o -c identify.c
nfct.o:nfct.c
	$(CC) $(CFLAGS) -o nfct.o  -c nfct.c

.PHONY: clean
clean:
	rm filter *.o
