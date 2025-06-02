#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#define BGPFILE "/home/www/fulltable/bgp.raw"
#define LBUF 100000
#define HASHELM 16777216UL

struct v4 {
  uint32_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
} **v4;
struct v6 {
  uint64_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
} **v6;
pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
int server_fd=-1;
uint8_t interrupted=0;
uint32_t follow=0,mask4[33],rxinfo=0,newinfo=0,tstart,trx,tnew,coll4=0,coll6=0,nv4,nv6;
uint64_t mask6[65];
struct lws *web_socket=NULL;
char *subscribe_message="{\"type\": \"ris_subscribe\", \"data\": {\"type\": \"UPDATE\", \"host\": \"rrc00\"}}";
char *lbuf;

static const signed char dd[256]={
  ['0']=0,['1']=1,['2']=2,['3']=3,['4']=4,['5']=5,['6']=6,['7']=7,
  ['8']=8,['9']=9,['A']=10,['B']=11,['C']=12,['D']=13,['E']=14,['F']=15,
  ['a']=10,['b']=11,['c']=12,['d']=13,['e']=14,['f']=15
};

uint32_t hv4(uint32_t ip4,uint8_t cidr){
  uint32_t h1=0x9747b28c,key;
  key=(ip4&0xFFFFFF00)|cidr;
  key*=0xcc9e2d51UL;
  key=(key<<15)|(key>>(32-15));
  key*=0x1b873593UL;
  h1^=key;
  h1=(h1<<13)|(h1>>(32-13));
  h1=h1*5+0xe6546b64;
  h1^=4;
  h1^=h1>>16;
  h1*=0x85ebca6b;
  h1^=h1>>13;
  h1*=0xc2b2ae35;
  h1^=h1>>16;
  return h1&0x00FFFFFF;
}

uint32_t hv6(uint64_t ip6,uint8_t cidr){
  uint64_t h1=0x9747b28c,key;
  key=(ip6&0xFFFFFFFFFFFFFF00ULL)|cidr;
  key*=0x87c37b91114253d5ULL;
  key=(key<<31)|(key>>(64-31));
  key*=0x4cf5ad432745937fULL;
  h1^=key;
  h1=(h1 << 27) | (h1 >> (64 - 27));
  h1=h1*5+0x52dce729;
  h1^=8;
  h1^=h1>>33;
  h1*=0xff51afd7ed558ccdULL;
  h1^=h1>>33;
  h1*=0xc4ceb9fe1a85ec53ULL;
  h1^=h1>>33;
  return (uint32_t)(h1&0xFFFFFF);
}

void myins(char *ptr,int len,uint32_t asn){
  uint32_t ts,ip4,q;
  uint64_t ip6;
  uint8_t a[4],cidr;
  uint16_t b[4];
  long i,j;

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
    if(cidr<16||cidr>48)return;
    q=hv6(ip6,cidr);
    if(v6[q]==NULL){
      v6[q]=(struct v6 *)malloc(sizeof(struct v6));
      if(v6[q]==NULL)exit(0);
      nv6++;
    }
    else if((v6[q]->ip!=ip6)||(v6[q]->cidr!=cidr))coll6++;
    v6[q]->ip=ip6;
    v6[q]->cidr=cidr;
    v6[q]->asn=asn;
    v6[q]->ts=ts;
    return;
  }
  for(i=-1,j=0;j<4;j++)for(a[j]=0,i++;i<len;i++)if((ptr[i]!='.'&&j<3) || (ptr[i]!='/'&&j==3))a[j]=a[j]*10+dd[ptr[i]]; else break;
  for(ip4=0,j=0;j<4;j++){ip4<<=8; ip4|=a[j];}
  for(cidr=0,i++;i<len;i++)cidr=cidr*10+dd[ptr[i]];
  if(cidr<8||cidr>32)return;
  q=hv4(ip4,cidr);
  if(v4[q]==NULL){
    v4[q]=(struct v4 *)malloc(sizeof(struct v4));
    if(v4[q]==NULL)exit(0);
    nv4++;
  }
  else if((v4[q]->ip!=ip4)||(v4[q]->cidr!=cidr))coll4++;
  v4[q]->ip=ip4;
  v4[q]->cidr=cidr;
  v4[q]->asn=asn;
  v4[q]->ts=ts;
  return;
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
      trx=time(NULL);
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
  uint32_t i,aaa;

  pthread_mutex_lock(&lock);
  switch(sig){
    case 34:
            for(aaa=0,i=0;i<HASHELM;i++)if(v4[i]!=NULL)aaa++;

        printf("run %lu %lu %lu\n",nv4,nv6,aaa);
break;
    
    case 36:
      for(nv4=0,i=0;i<HASHELM;i++)if(v4[i]!=NULL)nv4++;
      for(nv6=0,i=0;i<HASHELM;i++)if(v6[i]!=NULL)nv6++;
      fp=fopen(BGPFILE,"wb");
      fwrite(&nv4,4,1,fp);
      fwrite(&nv6,4,1,fp);
      for(i=0;i<HASHELM;i++)if(v4[i]!=NULL)fwrite(v4[i],sizeof(struct v4),1,fp);
      for(i=0;i<HASHELM;i++)if(v6[i]!=NULL)fwrite(v6[i],sizeof(struct v6),1,fp);
      fclose(fp);
      break;

    case 37:
      if(server_fd>=0)shutdown(server_fd,SHUT_RDWR);;
      interrupted=1;
      break;
  }
  pthread_mutex_unlock(&lock);
}

void *whois_server_thread(void *arg){
  int client_fd,opt;
  struct sockaddr_in addr;
  char buf[200],buft[15];
  ssize_t n;
  uint8_t a[4],cidr,nfound;
  int i,j,len;
  uint16_t b[4];
  uint32_t ip4,q;
  uint64_t ip6;
  long pos;
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
    n=read(client_fd,buf,199);
    if(n>0){
      pthread_mutex_lock(&lock);
      buf[n]='\0';
      len=n;
      nfound=0;
      for(i=0;i<len;i++)if(buf[i]=='.')break;
      if(i<len){
        for(j=0;j<4;j++)a[j]=0;
        for(i=-1,j=0;j<4;j++)for(a[j]=0,i++;i<len;i++)if((buf[i]!='.'&&j<3) || (buf[i]!='\0'&&j==3))a[j]=a[j]*10+dd[buf[i]]; else break;
        for(ip4=0,j=0;j<4;j++){ip4<<=8; ip4|=a[j];}
        for(cidr=24;cidr>=8;cidr--){
          q=hv4(ip4,cidr);
          if(v4[q]!=NULL){
            tt=(time_t)v4[pos]->ts;
            tm_info=localtime(&tt);
            strftime(buft,15,"%Y%m%d%H%M%S",tm_info);
            sprintf(buf,"%u %lu %s\n",cidr,v4[pos]->asn,buft);
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
        for(ip6=0,j=0;j<4;j++){ip6<<=16; ip6|=b[j];}
        for(cidr=48;cidr>=16;cidr--){
          q=hv6(ip6,cidr);
          if(v6[q]!=NULL){
            tt=(time_t)v6[pos]->ts;
            tm_info=localtime(&tt);
            strftime(buft,15,"%Y%m%d%H%M%S",tm_info);
            sprintf(buf,"%u %lu %s\n",cidr,v6[pos]->asn,buft);
            write(client_fd,buf,strlen(buf));
            nfound++;
          }
        }
      }
      tt=(time_t)tstart;
      tm_info=localtime(&tt);
      strftime(buft,15,"%Y%m%d%H%M%S",tm_info);
      sprintf(buf,"--\n%u match found\n%lu v4 elm\n%lu v4 collisions\n%lu v6 elm\n%lu v6 collisions\n%s start\n",nfound,nv4,coll4,nv6,coll6,buft);
      write(client_fd,buf,strlen(buf));
      tt=(time_t)trx;
      tm_info=localtime(&tt);
      strftime(buft,15,"%Y%m%d%H%M%S",tm_info);
      sprintf(buf,"%lu %s rx info\n",rxinfo,buft);
      write(client_fd,buf,strlen(buf));
      tt=(time_t)tnew;
      tm_info=localtime(&tt);
      strftime(buft,15,"%Y%m%d%H%M%S",tm_info);
      sprintf(buf,"%lu %s new info\n",newinfo,buft);
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
  uint32_t i,j,nv4,nv6,q;
  struct v4 av4;
  struct v6 av6;

  trx=tnew=tstart=time(NULL);

  printf("run 0\n");
  
  v4=(struct v4 **)malloc(HASHELM*sizeof(struct v4 *));
  if(v4==NULL)exit(0);
  for(i=0;i<HASHELM;i++)v4[i]=NULL;
  v6=(struct v6 **)malloc(HASHELM*sizeof(struct v6 *));
  if(v6==NULL)exit(0);
  for(i=0;i<HASHELM;i++)v6[i]=NULL;
  lbuf=(char *)malloc(LBUF);
  if(lbuf==NULL)exit(0);

  printf("run 1\n");

  fp=fopen(BGPFILE,"rb");
  if(fp!=NULL){
    fread(&nv4,4,1,fp);
    fread(&nv6,4,1,fp);
    printf("run %lu %lu\n",nv4,nv6);
    for(j=0;j<nv4;j++){
      fread(&av4,sizeof(struct v4),1,fp);
      q=hv4(av4.ip,av4.cidr);
      v4[q]=(struct v4 *)malloc(sizeof(struct v4));
      if(v4[q]==NULL)exit(0);
      v4[q]->ip=av4.ip;
      v4[q]->cidr=av4.cidr;
      v4[q]->asn=av4.asn;
      v4[q]->ts=av4.ts;
    }
    for(j=0;j<nv6;j++){
      fread(&av6,sizeof(struct v6),1,fp);
      q=hv6(av6.ip,av6.cidr);
      v6[q]=(struct v6 *)malloc(sizeof(struct v6));
      if(v6[q]==NULL)exit(0);
      v6[q]->ip=av6.ip;
      v6[q]->cidr=av6.cidr;
      v6[q]->asn=av6.asn;
      v6[q]->ts=av6.ts;
    }
    fclose(fp);
  }
  mask4[0]=0; for(i=1;i<33;i++)mask4[i]=~((1U<<(32-i))-1);
  mask6[0]=0; for(i=1;i<65;i++)mask6[i]=~((1UL<<(64-i))-1);
  signal(34,sigint_handler);
  signal(35,sigint_handler);
  signal(36,sigint_handler);
  signal(37,sigint_handler);

  printf("run 2\n");
  
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


  printf("run %lu %lu\n",nv4,nv6);

  
  pthread_create(&whois_thread,NULL,whois_server_thread,NULL);
  while(!interrupted){
    lws_service(context,100);
  }
  lws_context_destroy(context);
  pthread_join(whois_thread,NULL);
  return 0;
}
