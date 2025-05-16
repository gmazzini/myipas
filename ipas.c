#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>
#include <ctype.h>
#include <pthread.h>

#define BUFMSG 10000
#define NTHREAD 256
#define LISTENPORT 5555
#define TOTNETS 2000000
#define MAXSTEPS 40
#define FILENETS "/home/www/fulltable/m4.txt"

struct v4 {
  uint32_t ipv4;
  uint8_t cidr;
  uint32_t as;
};
struct arg_pass {
  char *mesg;
  int lenmesg;
  struct sockaddr_in cliaddr;
};

pthread_t *tid;
int sockfd;
struct v4 *v4=NULL;
uint32_t mymask[33];
uint32_t totipasclass,totallquery,totmalformed;

static int myipcmp(const void *p1, const void *p2){
  long ret;
  ret=((struct v4 *)p1)->ipv4-((struct v4*)p2)->ipv4;
  if(ret==0)return 0;
  return (ret>0)?1:-1;
}

long myipsearch(unsigned long ip_tocheck){
  long zinit,zend,myclass;
  unsigned long ip_mask;
  int i;
  
  zinit=0;
  zend=totipasclass-1;
  for(i=0;i<MAXSTEPS;i++){
    myclass=(zinit+zend)/2;
    ip_mask=mymask[v4[myclass].cidr];
    if((ip_tocheck&ip_mask)==v4[myclass].ipv4)break;
    if((ip_tocheck&ip_mask)>v4[myclass].ipv4)zinit=myclass+1;
    else zend=myclass-1;
    if(zinit>zend||zinit>=totipasclass||zend<0)return -1;
  }
  return myclass;
}

void myconfig(){
  FILE *fp;
  int i,ii,j;
  char buf[BUFMSG];
  struct sockaddr_in netip;
  
  fp=fopen(FILENETS,"rt");
  for(totipasclass=0;;){
    if(fgets(buf,BUFMSG,fp)==NULL)break;
    if(buf[0]=='#')continue;
    j=strlen(buf);
    for(i=0;i<j;i++)if(buf[i]=='/')break;
    if(i==j)continue;
    buf[i]='\0';
    for(ii=i+1;ii<j;ii++)if(buf[ii]==',')break;
    if(i==j)continue;
    buf[ii]='\0';
    inet_pton(AF_INET,buf,&(netip.sin_addr));
    v4[totipasclass].cidr=atoi(buf+i+1);
    v4[totipasclass].as=atoi(buf+ii+1);
    v4[totipasclass].ipv4=ntohl(netip.sin_addr.s_addr)&mymask[v4[totipasclass].cidr];
    totipasclass++;
  }
  fclose(fp);
  qsort(v4,totipasclass,sizeof(struct v4),myipcmp);
}

void *manage(void *arg_void){
  struct arg_pass *myarg=(struct arg_pass *)arg_void;
  int lenrecv,i,j,ml,lenaux,lenanswer,mystop;
  long myclass;
  unsigned int query;
  unsigned long asret;
  unsigned long ipsrcaddr;
  struct sockaddr_in netip;
  char *recv,*auxbuf,*dominio,*aux1,*aux2;
  
  recv=(char *)malloc(BUFMSG*sizeof(char));
  auxbuf=(char *)malloc(BUFMSG*sizeof(char));
  dominio=(char *)malloc(BUFMSG*sizeof(char));
  
  mystop=0;
  // QR B2 b7
  if(!mystop && ((*(myarg->mesg+2))&0b10000000)!=0){mystop=1; totmalformed++; }
  // AA B2 b2
  if(!mystop && ((*(myarg->mesg+2))&0b00000100)!=0){mystop=1; totmalformed++; }
  // Z B3 b6
  if(!mystop && ((*(myarg->mesg+3))&0b01000000)!=0){mystop=1; totmalformed++; }
  // Rcode B3 b3-0
  if(!mystop && ((*(myarg->mesg+3))&0b00001111)!=0){mystop=1; totmalformed++; }
  // Total Answer B6 B7
  if(!mystop && (*(myarg->mesg+6))!=0){mystop=1; totmalformed++; }
  if(!mystop && (*(myarg->mesg+7))!=0){mystop=1; totmalformed++; }
  
  if(!mystop){
    lenanswer=0;
    for(i=0,aux1=dominio,aux2=myarg->mesg+12;;){
      ml=(int)*aux2;
      if(ml==0)break;
      aux2++;
      i+=ml;
      if(i>=BUFMSG){mystop=1; totmalformed++; break;}
      for(j=0;j<ml;j++)*aux1++=tolower(*aux2++);
      i++;
      if(i>=BUFMSG){mystop=1; totmalformed++; break;}
      *aux1++='.';
      lenanswer+=ml+1;
    }
    if(i==0)*aux1='\0';
    else *(--aux1)='\0';
  }
  
  if(!mystop){
    totallquery++;
    query=*(aux2+2);
    lenanswer+=5;    
    if(query==16 && strncmp(dominio,"cmd",3)==0){
      for(aux1=dominio;*aux1!='\0';aux1++)if(*aux1=='/')break;
      if(*aux1=='\0')sprintf(auxbuf,"request malfomed");
      else {
        for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
        if(*aux1=='\0')sprintf(auxbuf,"missed command");
        else {
          *aux1='\0';
          if(strcmp(aux2,"reload")==0){
            myconfig();
            sprintf(auxbuf,"configuration reloaded");
          }
          else if(strcmp(aux2,"ipas")==0){
            for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
            if(*aux1=='\0')sprintf(auxbuf,"missed source IP");
            else {
              *aux1='\0';
              inet_pton(AF_INET,aux2,&(netip.sin_addr));
              ipsrcaddr=ntohl(netip.sin_addr.s_addr);
              for(i=32;i>=8;i--){
                myclass=myipsearch(ipsrcaddr&mymask[i]);
                if(myclass!=-1)break;
              }
              if(myclass>=0)asret=v4[myclass].as;
              else asret=0;
              sprintf(auxbuf,"%ld %s",asret,aux2);
            }
          }
          else if(strcmp(aux2,"status")==0){
            sprintf(auxbuf,"totallquery=%'lu totmalformed=%'lu",totallquery,totmalformed);
          }
          else if(strcmp(aux2,"reset")==0){
            totallquery=totmalformed=0;
            sprintf(auxbuf,"counters reset");
          }
          else sprintf(auxbuf,"command unknown %s",aux2);
        }
      }
      lenaux=strlen(auxbuf);
      lenrecv=12+lenanswer+13+lenaux;
      if(lenrecv<BUFMSG){
        recv[0]=*myarg->mesg; recv[1]=*(myarg->mesg+1); recv[2]=129; recv[3]=128; recv[4]=*(myarg->mesg+4); recv[5]=*(myarg->mesg+5); recv[6]=0; recv[7]=1; recv[8]=0; recv[9]=0; recv[10]=0; recv[11]=0;
        memcpy(recv+12,myarg->mesg+12,lenanswer);
        aux1=recv+12+lenanswer;
        aux1[0]=192; aux1[1]=12; aux1[2]=0; aux1[3]=16; aux1[4]=0; aux1[5]=1; aux1[6]=0; aux1[7]=0; aux1[8]=14; aux1[9]=16; aux1[10]=0; aux1[12]=lenaux; aux1[11]=aux1[12]+1;
        memcpy(aux1+13,auxbuf,lenaux);
      }
    }
    sendto(sockfd,recv,lenrecv,0,(struct sockaddr *)&myarg->cliaddr,sizeof(myarg->cliaddr));
  }
  free(recv);
  free(auxbuf);
  free(dominio);
  return NULL;
}

int main(int argc, char**argv){
  struct arg_pass *myargs;
  int i,j;
  socklen_t len;
  struct sockaddr_in servaddr;
  
  for(i=0;i<=32;i++)mymask[i]=~((1<<(32-i))-1);
  v4=(struct v4 *)malloc(TOTNETS*sizeof(struct v4));
  tid=(pthread_t *)malloc(NTHREAD*sizeof(pthread_t));
  myargs=(struct arg_pass *)malloc(NTHREAD*sizeof(struct arg_pass));
  for(i=0;i<NTHREAD;i++)myargs[i].mesg=(char *)malloc(BUFMSG*sizeof(char));
  totallquery=totmalformed=0;
  
  myconfig();
  
  sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
  memset((char *)&servaddr,0,sizeof(servaddr));
  servaddr.sin_family=AF_INET;
  servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
  servaddr.sin_port=htons(LISTENPORT);
  bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
  len=sizeof(struct sockaddr_in);
  
  for(j=0;;){
    myargs[j].lenmesg=recvfrom(sockfd,myargs[j].mesg,BUFMSG,0,(struct sockaddr *)&myargs[j].cliaddr,&len);
    pthread_create(&(tid[j]),NULL,&manage,&myargs[j]);
    pthread_detach(tid[j]);
    if(++j==NTHREAD)j=0;
  }
}
