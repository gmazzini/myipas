#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#define V4FILE "/home/www/fulltable/m4.txt"
#define V6FILE "/home/www/fulltable/m6.txt"
#define PARFILE "/home/www/fulltable/par.txt"
#define BKP4FILE "/home/www/fulltable/bkp4.raw"
#define BKP6FILE "/home/www/fulltable/bkp6.raw"
#define LENELM 10000000
#define LBUF 100000

struct v4 {
  uint32_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
} *v4;
struct v6 {
  uint64_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
} *v6;
long elmv4=0,elmv6=0;
pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
int server_fd=-1;

uint8_t interrupted=0;
uint32_t follow=0,mask4[33],rxinfo=0,newinfo=0;
uint64_t mask6[65];
struct lws *web_socket=NULL;
char *subscribe_message="{\"type\": \"ris_subscribe\", \"data\": {\"type\": \"UPDATE\", \"host\": \"rrc00\"}}";
char *lbuf;

static const signed char dd[256]={
  ['0']=0,['1']=1,['2']=2,['3']=3,['4']=4,['5']=5,['6']=6,['7']=7,
  ['8']=8,['9']=9,['A']=10,['B']=11,['C']=12,['D']=13,['E']=14,['F']=15,
  ['a']=10,['b']=11,['c']=12,['d']=13,['e']=14,['f']=15
};

void myins(char *ptr,int len,uint32_t asn){
  uint32_t ip4,ts;
  uint8_t found,a[4],cidr;
  uint64_t ip6,b[4];
  long start,end,pos,i,j;
  
  ts=time(NULL);
  for(i=0;i<len;i++)if(ptr[i]==':'){
    for(j=0;j<4;j++)b[j]=0;
    for(i=-1,j=0;j<4;j++){
      for(i++;i<len;i++)if(ptr[i]!=':' && ptr[i]!='/')b[j]=b[j]*16+dd[ptr[i]]; else break;
      if(ptr[i+1]==':')for(i++;i<len;i++)if(ptr[i]=='/')break;
      if(ptr[i]=='/')break;
    }
    for(ip6=0,j=0;j<4;j++){ip6<<=16; ip6|=b[j];}
    for(cidr=0,i++;i<len;i++)cidr=cidr*10+dd[ptr[i]];
    if(cidr>128)return;
    if(elmv6==0){
      pos=0;
      elmv6=1;
    }
    else {
      start=0;
      end=elmv6-1;
      found=0;
      while(start<=end){
        pos=start+(end-start)/2;
        if(ip6==v6[pos].ip && cidr==v6[pos].cidr){found=1; break;}
        else if(ip6>v6[pos].ip || (ip6==v6[pos].ip && cidr>v6[pos].cidr))start=pos+1;
        else end=pos-1;
      }
      if(!found){
        if(elmv6>=LENELM){interrupted=1; return;}
        pos=start;
        for(i=elmv6;i>pos;i--)v6[i]=v6[i-1];
        elmv6++;
        newinfo++,
      }
    }
    v6[pos].ip=ip6;
    v6[pos].cidr=cidr;
    v6[pos].asn=asn;
    v6[pos].ts=ts;
    return;
  }

  for(i=-1,j=0;j<4;j++)for(a[j]=0,i++;i<len;i++)if((ptr[i]!='.'&&j<3) || (ptr[i]!='/'&&j==3))a[j]=a[j]*10+dd[ptr[i]]; else break;
  for(ip4=0,j=0;j<4;j++){ip4<<=8; ip4|=a[j];}
  for(cidr=0,i++;i<len;i++)cidr=cidr*10+dd[ptr[i]];
  if(cidr>32)return;
  if(elmv4==0){
    pos=0;
    elmv4=1;
  }
  else {
    start=0;
    end=elmv4-1;
    found=0;
    while(start<=end){
      pos=start+(end-start)/2;
      if(ip4==v4[pos].ip && cidr==v4[pos].cidr){found=1; break;}
      else if(ip4>v4[pos].ip || (ip4==v4[pos].ip && cidr>v4[pos].cidr))start=pos+1;
      else end=pos-1;
    }
    if(!found){
      if(elmv4>=LENELM){interrupted=1; return;}
      pos=start;
      for(i=elmv4;i>pos;i--)v4[i]=v4[i-1];
      elmv4++;
      newinfo++;
    }
  }
  v4[pos].ip=ip4;
  v4[pos].cidr=cidr;
  v4[pos].asn=asn;
  v4[pos].ts=ts;
}

int callback_ris(struct lws *wsi,enum lws_callback_reasons reason,void *user,void *in,size_t len){
  unsigned char aux[LWS_PRE+512];
  uint32_t j,asn;
  size_t msg_len;
  char *ptr,*buf1,*buf2,*buf3;

  pthread_mutex_lock(&lock);
  switch (reason){
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
      lws_callback_on_writable(wsi);
      lws_set_timer_usecs(wsi,10*LWS_USEC_PER_SEC);
      break;
    case LWS_CALLBACK_CLIENT_WRITEABLE:
      msg_len=strlen(subscribe_message);
      memcpy(&aux[LWS_PRE],subscribe_message,msg_len);
      lws_write(wsi,&aux[LWS_PRE],msg_len,LWS_WRITE_TEXT);
      break;
    case LWS_CALLBACK_CLIENT_RECEIVE:
      rxinfo++;
      ptr=(char *)in;
      if(ptr[len-1]!='}'){memcpy(lbuf+follow,ptr,len); follow+=len;  break;}
      if(follow>0){memcpy(lbuf+follow,ptr,len); len+=follow; follow=0; ptr=lbuf;}        
      ptr[len]='\0';  
      buf1=strstr(ptr,"\"path\":["); if(buf1==NULL)break;
      buf1+=8;
      buf2=strstr(buf1,"]"); if(buf2==NULL)break;
      *buf2='\0';
      for(;;){
        buf3=strstr(buf1,",");
        if(buf3!=NULL)buf1=buf3+1;
        else {
          for(asn=0,j=0;j<buf2-buf1;j++)asn=asn*10+dd[buf1[j]];
          break;
        }
      }
      buf1=strstr(buf2+1,"\"prefixes\":["); if(buf1==NULL)break;
      buf1+=12;
      buf2=strstr(buf1,"]"); if(buf2==NULL)break;
      *buf2='\0';
      for(;;){
        buf3=strstr(buf1,",");
        if(buf3!=NULL){
          myins(buf1+1,buf3-buf1-2,asn);
          buf1=buf3+1;
        }
        else {
          myins(buf1+1,buf2-buf1-2,asn);
          break;
        }
      }
      break;
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
      fprintf(stderr,"No Connection\n");
      interrupted=1;
      break;
    case LWS_CALLBACK_CLOSED:
      fprintf(stderr,"Closed Connection\n");
      interrupted=1;
      break;
    case LWS_CALLBACK_CLIENT_RECEIVE_PONG:
      break;
    case LWS_CALLBACK_TIMER:
      const char *ping_msg = "{\"type\": \"ping\"}";
      msg_len=strlen(ping_msg);
      memcpy(&aux[LWS_PRE],ping_msg,msg_len);
      lws_write(wsi,&aux[LWS_PRE],msg_len,LWS_WRITE_TEXT);
      lws_set_timer_usecs(wsi,10*LWS_USEC_PER_SEC);
      break;
    default:
      break;
  }
  pthread_mutex_unlock(&lock);
  return 0;
}

struct lws_protocols protocols[]={
  {.name="ris-protocol",.callback=callback_ris,.per_session_data_size=0,.rx_buffer_size=65536,},
  {NULL,NULL,0,0}
};

void sigint_handler(int sig){
  FILE *fp;
  uint32_t i,j,q,ip4,ts,dts,c4[33],c6[129];
  uint8_t a[4];
  uint64_t b[4],ip6;
  char buf[100];

  pthread_mutex_lock(&lock);
  ts=time(NULL);
  dts=1000000000;
  fp=fopen(PARFILE,"rt");
  if(fp!=NULL){
    fgets(buf,100,fp);
    dts=strtoul(buf,NULL,10);
    fclose(fp);
  }
  switch(sig){
    case SIGUSR1:
      for(i=0;i<33;i++)c4[i]=0;
      for(j=0,i=0;i<elmv4;i++)if(ts-v4[i].ts<dts){v4[j]=v4[i]; c4[v4[j].cidr]++; j++;}
      elmv4=j;
      if(elmv4==0)break;
      fp=fopen(V4FILE,"wt");
      fprintf(fp,"# v4_tot: %lu\n",elmv4);
      for(i=0;i<33;i++)if(c4[i]>0)fprintf(fp,"# v4_cidr%d: %lu\n",i,c4[i]);
      for(i=0;i<elmv4;i++){
        for(ip4=v4[i].ip,j=0;j<4;j++){a[j]=ip4&0xff; ip4>>=8;}
        fprintf(fp,"%d.%d.%d.%d",a[3],a[2],a[1],a[0]);
        fprintf(fp,"/%d,%lu\n",v4[i].cidr,v4[i].asn);
      }
      fclose(fp);
      break;
    
    case SIGUSR2:
      for(i=0;i<129;i++)c6[i]=0;
      for(j=0,i=0;i<elmv6;i++)if(ts-v6[i].ts<dts){v6[j]=v6[i]; c6[v6[j].cidr]++; j++;}
      elmv6=j;
      if(elmv6==0)break;
      fp=fopen(V6FILE,"wt");
      fprintf(fp,"# v6_tot: %lu\n",elmv6);
      for(i=0;i<129;i++)if(c6[i]>0)fprintf(fp,"# v6_cidr%d: %lu\n",i,c6[i]);
      for(i=0;i<elmv6;i++){
        for(ip6=v6[i].ip,q=0;q<64;q++)if(ip6&1)break; else ip6>>=1;
        for(ip6=v6[i].ip,j=0;j<4;j++){b[j]=ip6&0xffff; ip6>>=16;}
        if(q>=48)fprintf(fp,"%x::",b[3]);
        else if(q>=32)fprintf(fp,"%x:%x::",b[3],b[2]);
        else if(q>=16)fprintf(fp,"%x:%x:%x::",b[3],b[2],b[1]);
        else fprintf(fp,"%x:%x:%x:%x::",b[3],b[2],b[1],b[0]);
        fprintf(fp,"/%d,%lu\n",v6[i].cidr,v6[i].asn);
      }
      fclose(fp);
      break;
    
    case SIGINT:
      fp=fopen(BKP4FILE,"wb");
      fwrite(&elmv4,4,1,fp);
      fwrite(v4,sizeof(struct v4),elmv4,fp);
      fclose(fp);
      fp=fopen(BKP6FILE,"wb");
      fwrite(&elmv6,4,1,fp);
      fwrite(v6,sizeof(struct v6),elmv6,fp);
      fclose(fp);
      if(server_fd>=0)shutdown(server_fd,SHUT_RDWR);;
      interrupted=1;
      break;
  }
  pthread_mutex_unlock(&lock);
}

void *whois_server_thread(void *arg){
  int client_fd,opt;
  struct sockaddr_in addr;
  char buf[100],buft[15];
  ssize_t n;
  uint8_t a[4],found,cidr,nfound;
  int i,j,len;
  uint16_t b[4];
  uint32_t ip4,ip4org;
  uint64_t ip6,ip6org;
  long start,end,pos;
  time_t tt;
  struct tm *tm_info;

  server_fd=socket(AF_INET,SOCK_STREAM,0);
  opt=1;
  setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
  addr.sin_family=AF_INET;
  addr.sin_addr.s_addr=INADDR_ANY;
  addr.sin_port=htons(43);
  bind(server_fd,(struct sockaddr *)&addr,sizeof(addr));
  listen(server_fd,5);
  while(!interrupted){
    client_fd=accept(server_fd,NULL,NULL);
    if(client_fd<0)continue;
    n=read(client_fd,buf,99);
    if(n>0){
      pthread_mutex_lock(&lock);
      buf[n]='\0';
      len=n;
      nfound=0;
      for(i=0;i<len;i++)if(buf[i]=='.')break;
      if(i<len){
        for(j=0;j<4;j++)a[j]=0;
        for(i=-1,j=0;j<4;j++)for(a[j]=0,i++;i<len;i++)if((buf[i]!='.'&&j<3) || (buf[i]!='\0'&&j==3))a[j]=a[j]*10+dd[buf[i]]; else break;
        for(ip4org=0,j=0;j<4;j++){ip4org<<=8; ip4org|=a[j];}
        for(cidr=24;cidr>=8;cidr--){
          ip4=ip4org&mask4[cidr];
          start=0;
          end=elmv4-1;
          found=0;
          while(start<=end){
            pos=start+(end-start)/2;
            if(ip4==v4[pos].ip && cidr==v4[pos].cidr){found=1; break;}
            else if(ip4>v4[pos].ip || (ip4==v4[pos].ip && cidr>v4[pos].cidr))start=pos+1;
            else end=pos-1;
          }
          if(found){
            tt=(time_t)v4[pos].ts;
            tm_info=localtime(&tt);
            strftime(buft,15,"%Y%m%d%H%M%S",tm_info);
            sprintf(buf,"%u %lu %s\n",cidr,v4[pos].asn,buft);
            write(client_fd,buf,strlen(buf));
            nfound++;
          }
        }
      }
      else {
        for(j=0;j<4;j++)b[j]=0;
        for(i=-1,j=0;j<4;j++){
          for(i++;i<len;i++)if(buf[i]!=':' && buf[i]!='\0')b[j]=b[j]*16+dd[buf[i]]; else break;
          if(buf[i]=='\0' || buf[i+1]==':')break;
        }
        for(ip6org=0,j=0;j<4;j++){ip6org<<=16; ip6org|=b[j];}
        for(cidr=64;cidr>=16;cidr--){
          ip6=ip6org&mask6[cidr];
          start=0;
          end=elmv6-1;
          found=0;
          while(start<=end){
            pos=start+(end-start)/2;
            if(ip6==v6[pos].ip && cidr==v6[pos].cidr){found=1; break;}
            else if(ip6>v6[pos].ip || (ip6==v6[pos].ip && cidr>v6[pos].cidr))start=pos+1;
            else end=pos-1;
          }
          if(found){
            tt=(time_t)v6[pos].ts;
            tm_info=localtime(&tt);
            strftime(buft,15,"%Y%m%d%H%M%S",tm_info);
            sprintf(buf,"%u %lu %s\n",cidr,v6[pos].asn,buft);
            write(client_fd,buf,strlen(buf));
            nfound++;
          }
        }
      }
      sprintf(buf,"--\n%u match found\n%lu v4 elm\n%lu v6 elm\n%lu rx info\n%lu new info\n",nfound,elmv4,elmv6,rxinfo,newinfo);
      write(client_fd,buf,strlen(buf));
      pthread_mutex_unlock(&lock);
    }
    close(client_fd);
  }
  close(server_fd);
  return NULL;
}

int main(void) {
  struct lws_context_creation_info info;
  struct lws_client_connect_info ccinfo={0};
  struct lws_context *context;
  pthread_t whois_thread;
  FILE *fp;
  uint8_t i;

  v4=(struct v4 *)malloc(LENELM*sizeof(struct v4));
  if(v4==NULL)exit(0);
  v6=(struct v6 *)malloc(LENELM*sizeof(struct v6));
  if(v6==NULL)exit(0);
  lbuf=(char *)malloc(LBUF);
  if(lbuf==NULL)exit(0);
  fp=fopen(BKP4FILE,"rb");
  if(fp!=NULL){
    fread(&elmv4,4,1,fp);
    fread(v4,sizeof(struct v4),elmv4,fp);
    fclose(fp);
  }
  fp=fopen(BKP6FILE,"rb");
  if(fp!=NULL){
    fread(&elmv6,4,1,fp);
    fread(v6,sizeof(struct v6),elmv6,fp);
    fclose(fp);
  }
  mask4[0]=0; for(i=1;i<33;i++)mask4[i]=~((1U<<(32-i))-1);
  mask6[0]=0; for(i=1;i<65;i++)mask6[i]=~((1UL<<(64-i))-1);
  signal(SIGINT,sigint_handler);
  signal(SIGUSR1,sigint_handler);
  signal(SIGUSR2,sigint_handler);
  
  memset(&info,0,sizeof(info));
  info.port=CONTEXT_PORT_NO_LISTEN;
  info.protocols=protocols;
  info.options=LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
  context=lws_create_context(&info);
  ccinfo.context=context;
  ccinfo.address="ris-live.ripe.net";
  ccinfo.port=443;
  ccinfo.path="/v1/ws/";
  ccinfo.host=ccinfo.address;
  ccinfo.origin=ccinfo.address;
  ccinfo.protocol=protocols[0].name;
  ccinfo.ssl_connection=LCCSCF_USE_SSL;
  web_socket=lws_client_connect_via_info(&ccinfo);
  
  pthread_create(&whois_thread,NULL,whois_server_thread,NULL);
  while(!interrupted){
    lws_service(context,100);
  }
  lws_context_destroy(context);
  pthread_join(whois_thread,NULL);
  return 0;
}
