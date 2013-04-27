#include "stdxh.h"
#include "identify.h"
unsigned int markmask = 0xffffffff;
unsigned int maskfirstbit = 0;
unsigned int masknbits = 32;


int  new_identifiter(char * filename,struct identifier ** hook){
    FILE * init;
    int num=0,i;
    char  str[STR_LEN];
    char *pch,*preprocess;
    struct identifier * ret;
    if(init = fopen(filename,"r")){
        /*
        while(!feof(init)){
            fgets(str,STR_LEN,init); 
                ++num; 
        }
        */
        while(1){
            fgets(str,STR_LEN,init); 
            if(feof(init)) break;
                ++num; 
        }
        fseek(init, 0 , SEEK_SET);
        if(num > 0){
            ret = (struct identifier *) malloc(sizeof(struct identifier)*num);
        }
        else{
            return 0; 
        }
        for(i=0 ; i<num ;++i){
            fgets(str,STR_LEN,init); 
            pch = strtok(str," \n");
            strcpy(ret[i].name,pch);
            pch = strtok(NULL," \n");
            if(atoi(pch)<3){
                fprintf(stderr,"0,1,2 mark value is reserved!\n");
                exit(1);
            }
            ret[i].mark = atoi(pch);
            pch = strtok(NULL," \n");
            strcpy(ret[i].pattern,pch);
            preprocess = pre_process(ret[i].pattern);
            if (regcomp(&(ret[i].preg),preprocess,REG_EXTENDED|REG_NEWLINE)!=0){
                fprintf(stderr,"Compiling pre_process error!\n");
                exit(1);
            }
        } 
        *hook = ret;
        return num;
    }
    else{
        fprintf(stderr,"Configure file open error!\n");
        exit(1);
    }
}

/*
int set_identifier(struct identifier * iden,
                   char *name, 
                   char *pattern, 
                   int mark
                  // int eflags, int cflags ,
                   ){
    if(!(strlen(name)<IDEN_NAME_LEN && strlen(pattern)<IDEN_PATTERN_LEN)){
        fprintf(stderr,"The name or pattern of identifier is too long!\n");
        return -1;
    }
    strcpy(iden->name , name);
    strcpy(iden->pattern,pattern);
   // iden->eflags = eflags;
    //iden->cflags = cflags;
    iden->mark = mark;
    char * preprocessed  = pre_process(iden->pattern); 
    int rc = regcomp(&preg , preprocessed , REG_EXTENDED);
    if (rc != 0 ){
        fprintf("Error compiling %s -- %s \n",iden->name , iden->pattern); 
        exit(1);
    }
    return 0
}
*/

char * pre_process(const char *s){
   char * result = (char *)malloc(strlen(s) + 1);
  unsigned int sindex = 0, rindex = 0;
  while( sindex < strlen(s) ) {
    if( sindex + 3 < strlen(s) && s[sindex] == '\\' && s[sindex+1] == 'x' && 
	isxdigit(s[sindex + 2]) && isxdigit(s[sindex + 3]) ){

      result[rindex] = hex2dec(s[sindex + 2])*16 + hex2dec(s[sindex + 3]);

      switch ( result[rindex] ) {
        case '$':
        case '(':
        case ')':
        case '*':
        case '+':
        case '.':
        case '?':
        case '[':
        case ']':
        case '^':
        case '|':
        case '{':
        case '}':
        case '\\':
        fprintf(stderr,"Warning: regexp contains a regexp control character");
          break;
        case '\0':
          fprintf(stderr,"Warning: null (\\x00) in layer7 regexp. \
                  A null terminates the regexp string!\n");
	      break;
        default:
          break;
      }
      sindex += 3; /* 4 total */
    }
    else
      result[rindex] = s[sindex];
      
    sindex++; 
    rindex++;
  }
  result[rindex] = '\0';

  return result;
      
}

int hex2dec(char c){
  switch (c){
    case '0' ... '9':
      return c - '0';
    case 'a' ... 'f':
      return c - 'a' + 10;
    case 'A' ... 'F':
      return c - 'A' + 10;
    default:
      fprintf(stderr,"Bad regluar pattern encounter!\n");
      exit(1);
  }
  return 0;
}

int  iden_match(regex_t * pat , const char * buffer){
    int ret = regexec(pat,buffer,0,NULL,0);
    if(ret == 0 ) return 0;
    else return -1;
}


int classify(struct identifier *iden , int iden_num,const char *data ){
    int i;
    //printf("%s\n",data);
    for (i=0;i<iden_num;++i){
        if( iden_match(&(iden[i].preg),data)==0){
            return iden[i].mark; 
        } 
    }
    return NO_MATCH_YET;
}

