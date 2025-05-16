#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>
#include <ctype.h>
#include <pthread.h>

#define V4FILE "/home/www/fulltable/m4.txt"
#define V6FILE "/home/www/fulltable/m6.txt"


#define BUFMSG 10000
#define NTHREAD 256
#define LISTENPORT 5555
#define TOTNETS 2000000
#define MAXSTEPS 40
#define FILENETS "/home/www/fulltable/m4.txt"

static const signed char dd[256]={
  ['0']=0,['1']=1,['2']=2,['3']=3,['4']=4,['5']=5,['6']=6,['7']=7,
  ['8']=8,['9']=9,['A']=10,['B']=11,['C']=12,['D']=13,['E']=14,['F']=15,
  ['a']=10,['b']=11,['c']=12,['d']=13,['e']=14,['f']=15
};

struct v4 {
  uint32_t ip;
  uint8_t cidr;
  uint32_t asn;
} *v4;
struct v6 {
  uint64_t ip;
  uint8_t cidr;
  uint32_t asn;
} *v6;
struct arg_pass {
  char *mesg;
  int lenmesg;
  struct sockaddr_in cliaddr;
} *myarg;
long elmv4=0,elmv6=0;

pthread_t *tid;
int sockfd;

long mys4(uint32_t ip4,uint8_t cidr){
  long start,end,pos;
  uint8_t found;
  start=0;
  end=elmv4-1;
  found=0;
  while(start<=end){
    pos=start+(end-start)/2;
    if(ip4==v4[pos].ip && cidr==v4[pos].cidr){found=1; break;}
    else if(ip4>v4[pos].ip || (ip4==v4[pos].ip && cidr>v4[pos].cidr))start=pos+1;
    else end=pos-1;
  }
  if(found)return pos;
  else return -1;
}

void *manage(void *arg_void){
  struct arg_pass *myarg=(struct arg_pass *)arg_void;
  int lenrecv,i,j,ml,lenaux,lenanswer,mystop,len;
  long myclass;
  unsigned int query;
  unsigned long asret;
  char *recv,*auxbuf,*dominio,*aux1,*aux2;
  uint32_t ip4;
  uint8_t a[4];
  
  recv=(char *)malloc(BUFMSG*sizeof(char));
  auxbuf=(char *)malloc(BUFMSG*sizeof(char));
  dominio=(char *)malloc(BUFMSG*sizeof(char));
  
  mystop=0;
  if(!mystop && ((*(myarg->mesg+2))&0b10000000)!=0)mystop=1;
  if(!mystop && ((*(myarg->mesg+2))&0b00000100)!=0)mystop=1;
  if(!mystop && ((*(myarg->mesg+3))&0b01000000)!=0)mystop=1;
  if(!mystop && ((*(myarg->mesg+3))&0b00001111)!=0)mystop=1;
  if(!mystop && (*(myarg->mesg+6))!=0)mystop=1;
  if(!mystop && (*(myarg->mesg+7))!=0)mystop=1;
  
  if(!mystop){
    lenanswer=0;
    for(i=0,aux1=dominio,aux2=myarg->mesg+12;;){
      ml=(int)*aux2;
      if(ml==0)break;
      aux2++;
      i+=ml;
      if(i>=BUFMSG){mystop=1; break;}
      for(j=0;j<ml;j++)*aux1++=tolower(*aux2++);
      i++;
      if(i>=BUFMSG){mystop=1; break;}
      *aux1++='.';
      lenanswer+=ml+1;
    }
    if(i==0)*aux1='\0';
    else *(--aux1)='\0';
  }
  
  if(!mystop){
    query=*(aux2+2);
    lenanswer+=5;    
    if(query==16){
      aux1=dominio;
      len=strlen(dominio);
      for(i=-1,j=0;j<4;j++)for(a[j]=0,i++;i<len;i++)if(aux1[i]!='.')a[j]=a[j]*10+dd[aux1[i]]; else break;
      for(ip4=0,j=0;j<4;j++){ip4<<=8; ip4|=a[j];}
      for(i=32;i>=8;i--){
        myclass=mys4(ip4,i);
        if(myclass!=-1)break;
      }
      if(myclass>=0)asret=v4[myclass].asn;
      else asret=0;
      sprintf(auxbuf,"%ld %s",asret,aux2);
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

int main(){
  struct arg_pass *myargs;
  socklen_t lennn;
  struct sockaddr_in servaddr;

  uint32_t i,j,e,ip4,asn;
  uint8_t a[4],cidr,len;
  char buf[100],*buf1,*buf2;
  FILE *fp;
  
  fp=fopen(V4FILE,"rt");
  if(fp==NULL)return 0;
  fgets(buf,100,fp);
  buf1=buf+10;
  for(i=0;i<100;i++)if(buf1[i]!='\n')elmv4=elmv4*10+dd[buf1[i]]; else break;
  v4=(struct v4 *)malloc(elmv4*sizeof(struct v4));
  if(v4==NULL)return 0;
  for(e=0;;){
    if(fgets(buf,100,fp)==NULL)break;
    if(buf[0]=='#')continue;
    for(i=-1,j=0;j<4;j++)for(a[j]=0,i++;i<100;i++)if((buf[i]!='.'&&j<3) || (buf[i]!='/'&&j==3))a[j]=a[j]*10+dd[buf[i]]; else break;
    for(ip4=0,j=0;j<4;j++){ip4<<=8; ip4|=a[j];}
    for(cidr=0,i++;i<100;i++)if(buf[i]!=',')cidr=cidr*10+dd[buf[i]]; else break;
    for(asn=0,i++;i<len;i++)if(buf[i]!='\n')asn=asn*10+dd[buf[i]]; else break;
    v4[e].ip=ip4;
    v4[e].cidr=cidr;
    v4[e].asn=asn;
    e++;
  }
  fclose(fp);
  
  tid=(pthread_t *)malloc(NTHREAD*sizeof(pthread_t));
  myargs=(struct arg_pass *)malloc(NTHREAD*sizeof(struct arg_pass));
  for(i=0;i<NTHREAD;i++)myargs[i].mesg=(char *)malloc(BUFMSG*sizeof(char));
  sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
  memset((char *)&servaddr,0,sizeof(servaddr));
  servaddr.sin_family=AF_INET;
  servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
  servaddr.sin_port=htons(LISTENPORT);
  bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
  len=sizeof(struct sockaddr_in);
  
  for(j=0;;){
    myargs[j].lenmesg=recvfrom(sockfd,myargs[j].mesg,BUFMSG,0,(struct sockaddr *)&myargs[j].cliaddr,&lennn);
    pthread_create(&(tid[j]),NULL,&manage,&myargs[j]);
    pthread_detach(tid[j]);
    if(++j==NTHREAD)j=0;
  }
}
