#ifndef  IDENTIFY_H
#define  IDENTIFY_H

#include <regex.h>

#define  UNTOUCHED 0 
#define  NO_MATCH_YET 1 
#define  NO_MATCH 2 

#define  IDEN_NAME_LEN 32
#define  IDEN_PATTERN_LEN 512
#define  STR_LEN 1024

struct identifier{
    int mark;//this is the mark as ti appears in the config file 
             // before it goes to netfilter , it will get modified by mask
    char  name[IDEN_NAME_LEN];
    char  pattern[IDEN_PATTERN_LEN];
//    int eflags;  //for regexec
 //   int cflags;  //for regcomp
    regex_t preg; // the compiled regex
};

//int add_identifier_from_file(const char * filename,int mark);   
int hex2dec(char c);
char * pre_process(const char *s);

int new_identifiter(char * filename,struct identifier **hook) ;
/*
int set_identifier(struct identifier * iden,
                   char * name, 
                   char * pattern,
                   int mark
                   //int eflags, int cflags 
                   );
*/
////////////
int classify(struct identifier * iden, int iden_num,const char * data);
int iden_match(regex_t * pat ,const char * buffer);


#endif
