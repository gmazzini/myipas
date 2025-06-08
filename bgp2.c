#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <locale.h>
#define BGPFILE "/home/www/fulltable/bgp.raw"
#define TIMEOUT_RX 20
#define LBUF 100000
#define V4HASHBIT 28
#define V6HASHBIT 29
#define V4HASHELM (1UL<<V4HASHBIT)
#define V4HASHOUT ((1UL<<V4HASHBIT)-1) 
#define V6HASHELM (1UL<<V6HASHBIT)
#define V6HASHOUT ((1UL<<V6HASHBIT)-1) 
#define V4MAX 1800000
#define V6MAX 400000

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
pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
int server_fd=-1;
uint8_t interrupted=0;
uint32_t follow=0,mask4[33],rxv4=0,rxv6=0,newv4=0,newv6=0,tstart,trx,tnew,coll4=0,coll6=0,nv4,nv6,*v4i,*v6i,query=0,restart=0;
uint64_t mask6[65];
struct lws *web_socket=NULL;
char *subscribe_message="{\"type\": \"ris_subscribe\", \"data\": {\"type\": \"UPDATE\", \"host\": \"rrc00\"}}";
char *lbuf;

static const signed char dd[256]={
  ['0']=0,['1']=1,['2']=2,['3']=3,['4']=4,['5']=5,['6']=6,['7']=7,
  ['8']=8,['9']=9,['A']=10,['B']=11,['C']=12,['D']=13,['E']=14,['F']=15,
  ['a']=10,['b']=11,['c']=12,['d']=13,['e']=14,['f']=15
};

#if V4HASHBIT < 28
uint32_t hv4(uint32_t ip,uint8_t cidr){
  uint32_t x;
  x=(ip&mask4[cidr])>>8;
  x=(x^(cidr*0x45D9F3B))*0x119DE1F3;
  x^=x>>16;
  x^=x>>8;
  return x&V4HASHOUT;
}
#else
uint32_t hv4(uint32_t ip,uint8_t cidr){
  uint32_t x,y;
  if(cidr<8||cidr>24)return 0;
  if(cidr==8){
    x=10UL<<16;
    x|=((ip&0xff000000)>>16);
    return x;
  }
  x=(ip&mask4[cidr])>>8;
  y=cidr-9;
  x|=(y<<24);
  return x;
}
#endif

uint32_t hv6(uint64_t ip,uint8_t cidr){
  uint64_t x;
  x=(ip&mask6[cidr])>>16;
  x=(x^(cidr*0x9E3779B97F4A7C15ULL))*0xC2B2AE3D27D4EB4FULL;
  x^=x>>33;
  x^=x>>17;
  return (uint32_t)(x&V6HASHOUT);
}

char *mydata(uint32_t x){
  time_t tt;
  struct tm *tm_info;
  static char buft[30];
  tt=(time_t)x; 
  tm_info=localtime(&tt); 
  strftime(buft,15,"%Y%m%d%H%M%S",tm_info);
  return buft;
}

void myproc(char *ptr,int len,uint32_t asn){
  uint32_t ts,ip4,q;
  uint64_t ip6;
  uint8_t a[4],cidr;
  uint16_t b[4];
  long i,j;
  struct v4 *aiv4;
  struct v6 *aiv6;
  
  ts=time(NULL);
  for(i=0;i<len;i++)if(ptr[i]==':'){
    rxv4++;
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
    if(v6i[q]==0){
      v6i[q]=nv6;
      nv6++;
      newv6++; 
      tnew=time(NULL);
      aiv6=v6+v6i[q];
    }
    else {
      aiv6=v6+v6i[q];
      if((aiv6->ip!=ip6)||(aiv6->cidr!=cidr))coll6++;
    } 
    aiv6->ip=ip6;
    aiv6->cidr=cidr;
    aiv6->asn=asn;
    aiv6->ts=ts;
    return;
  }
  rxv6++;
  for(i=-1,j=0;j<4;j++)for(a[j]=0,i++;i<len;i++)if((ptr[i]!='.'&&j<3) || (ptr[i]!='/'&&j==3))a[j]=a[j]*10+dd[ptr[i]]; else break;
  for(ip4=0,j=0;j<4;j++){ip4<<=8; ip4|=a[j];}
  for(cidr=0,i++;i<len;i++)cidr=cidr*10+dd[ptr[i]];
  if(cidr<8||cidr>24)return;
  q=hv4(ip4,cidr);
  if(v4i[q]==0){
    v4i[q]=nv4;
    nv4++;
    newv4++; 
    tnew=time(NULL);
    aiv4=v4+v4i[q];
  }
  else {
    aiv4=v4+v4i[q];
    if((aiv4->ip!=ip4)||(aiv4->cidr!=cidr))coll4++;
  }
  aiv4->ip=ip4;
  aiv4->cidr=cidr;
  aiv4->asn=asn;
  aiv4->ts=ts;
  return;
}

int callback_ris(struct lws *wsi,enum lws_callback_reasons reason,void *user,void *in,size_t len){
  unsigned char aux[LWS_PRE+512];
  unsigned char dummy_ping[LWS_PRE];
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
      trx=time(NULL);
      if(follow+len>=LBUF-1){follow=0; break;}
      memcpy(lbuf+follow,in,len);
      follow+=len;
      if(!lws_is_final_fragment(wsi))break;
      lbuf[follow]='\0';
      ptr=lbuf;
      len=follow;
      follow=0;
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
          myproc(buf1+1,buf3-buf1-2,asn);
          buf1=buf3+1;
        }
        else {
          myproc(buf1+1,buf2-buf1-2,asn);
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
      trx=time(NULL); 
      break;
    case LWS_CALLBACK_TIMER:
      lws_write(wsi,dummy_ping+LWS_PRE,0,LWS_WRITE_PING);
      lws_set_timer_usecs(wsi,10*LWS_USEC_PER_SEC);
      break;
    default:
      break;
  }
  pthread_mutex_unlock(&lock);
  return 0;
}

struct lws_protocols protocols[]={
  {.name="ris-protocol",.callback=callback_ris,.per_session_data_size=0,.rx_buffer_size=131072,},
  {NULL,NULL,0,0}
};

void sigint_handler(int sig){
  FILE *fp;

  pthread_mutex_lock(&lock);
  switch(sig){
    case 36:
      fp=fopen(BGPFILE,"wb");
      fwrite(&nv4,4,1,fp);
      fwrite(&nv6,4,1,fp);
      fwrite(v4,sizeof(struct v4),nv4,fp);
      fwrite(v6,sizeof(struct v6),nv6,fp);
      fclose(fp);
      break;
    case 37:
      if(server_fd>=0)shutdown(server_fd,SHUT_RDWR);
      interrupted=1;
      break;
  }
  pthread_mutex_unlock(&lock);
}

void *whois_server_thread(void *arg){
  int client_fd,opt;
  struct sockaddr_in addr;
  char buf[200];
  ssize_t n;
  uint8_t a[4],cidr,nfound;
  int i,j,len;
  uint16_t b[4];
  uint32_t ip4,q;
  uint64_t ip6;
  struct v4 *aiv4;
  struct v6 *aiv6;

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
      if(strncmp(buf,"stat",4)==0){
        sprintf(buf,"%s Tstart\n",mydata(tstart)); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%s Trx\n",mydata(trx)); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%s Tnew\n",mydata(tnew)); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%10lu Nrestart\n",restart); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%10lu Nelm v4\n%10lu Ncollision v4\n%10lu Nrx v4\n%10lu Nnew v4\n",nv4-1,coll4,rxv4,newv4); write(client_fd,buf,strlen(buf));
        sprintf(buf,"%10lu Nelm v6\n%10lu Ncollision v6\n%10lu Nrx v6\n%10lu Nnew v6\n",nv6-1,coll6,rxv6,newv6); write(client_fd,buf,strlen(buf));
      }
      else {
        query++;
        len=n;
        nfound=0;
        for(i=0;i<len;i++)if(buf[i]=='.')break;
        if(i<len){
          for(j=0;j<4;j++)a[j]=0;
          for(i=-1,j=0;j<4;j++)for(a[j]=0,i++;i<len;i++)if((buf[i]!='.'&&j<3) || (buf[i]!='\0'&&j==3))a[j]=a[j]*10+dd[buf[i]]; else break;
          for(ip4=0,j=0;j<4;j++){ip4<<=8; ip4|=a[j];}
          for(cidr=24;cidr>=8;cidr--){
            q=hv4(ip4,cidr);
            if(v4i[q]!=0){
              aiv4=v4+v4i[q];
              sprintf(buf,"%u %lu %s\n",cidr,aiv4->asn,mydata(aiv4->ts)); write(client_fd,buf,strlen(buf));
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
            if(v6i[q]!=0){
              aiv6=v6+v6i[q];
              sprintf(buf,"%u %lu %s\n",cidr,aiv6->asn,mydata(aiv6->ts)); write(client_fd,buf,strlen(buf));
              nfound++;
            }
          }
        }
        sprintf(buf,"--\n%u match found\n%lu v4 elm\n%lu v6 elm\n%lu query\n",nfound,nv4-1,nv6-1,query); write(client_fd,buf,strlen(buf));
      }
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
  uint32_t i,j,q,anv4,anv6;
  struct v4 av4,*aiv4;
  struct v6 av6,*aiv6;

  setlocale(LC_NUMERIC,"en_US.UTF-8");
  tnew=tstart=time(NULL);
  v4=(struct v4 *)malloc(V4MAX*sizeof(struct v4));
  if(v4==NULL)exit(0);
  v4i=(uint32_t *)malloc(V4HASHELM*sizeof(uint32_t));
  if(v4i==NULL)exit(0);
  for(i=0;i<V4HASHELM;i++)v4i[i]=0;
  v4[0].ip=0; v4[0].cidr=0; v4[0].asn=0; v4[0].ts=0;
  nv4=1;
  v6=(struct v6 *)malloc(V6MAX*sizeof(struct v6));
  if(v6==NULL)exit(0);
  v6i=(uint32_t *)malloc(V6HASHELM*sizeof(uint32_t));
  if(v6i==NULL)exit(0);
  for(i=0;i<V6HASHELM;i++)v6i[i]=0;
  v6[0].ip=0; v6[0].cidr=0; v6[0].asn=0; v6[0].ts=0;
  nv6=1;
  mask4[0]=0; for(i=1;i<33;i++)mask4[i]=~((1U<<(32-i))-1);
  mask6[0]=0; for(i=1;i<65;i++)mask6[i]=~((1UL<<(64-i))-1);
  lbuf=(char *)malloc(LBUF);
  if(lbuf==NULL)exit(0);

  fp=fopen(BGPFILE,"rb");
  if(fp!=NULL){
    fread(&anv4,4,1,fp);
    fread(&anv6,4,1,fp);
    for(j=0;j<anv4;j++){
      fread(&av4,sizeof(struct v4),1,fp);
      q=hv4(av4.ip,av4.cidr);
      if(v4i[q]==0){   
        v4i[q]=nv4;
        nv4++;
      }
      aiv4=v4+v4i[q];
      aiv4->ip=av4.ip;
      aiv4->cidr=av4.cidr;
      aiv4->asn=av4.asn;
      aiv4->ts=av4.ts;
    }
    for(j=0;j<anv6;j++){
      fread(&av6,sizeof(struct v6),1,fp);
      q=hv6(av6.ip,av6.cidr);
      if(v6i[q]==0){
        v6i[q]=nv6;
        nv6++;
      }
      aiv6=v6+v6i[q];
      aiv6->ip=av6.ip;
      aiv6->cidr=av6.cidr;
      aiv6->asn=av6.asn;
      aiv6->ts=av6.ts;
    }
    fclose(fp);
  }
  signal(36,sigint_handler);
  signal(37,sigint_handler);
  
  pthread_create(&whois_thread,NULL,whois_server_thread,NULL);
  start_ws:
  
  memset(&info,0,sizeof(info));
  info.port=CONTEXT_PORT_NO_LISTEN;
  info.protocols=protocols;
  info.options=LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
  context=lws_create_context(&info);
  memset(&ccinfo,0,sizeof(ccinfo));
  ccinfo.context=context;
  ccinfo.address="ris-live.ripe.net";
  ccinfo.port=443;
  ccinfo.path="/v1/ws/";
  ccinfo.host=ccinfo.address;
  ccinfo.origin=ccinfo.address;
  ccinfo.protocol=protocols[0].name;
  ccinfo.ssl_connection=LCCSCF_USE_SSL;
  web_socket=lws_client_connect_via_info(&ccinfo);
  trx=time(NULL);
  while(!interrupted){
    lws_service(context,100);
    if(time(NULL)-trx>TIMEOUT_RX){
      restart++;
      lws_context_destroy(context);
      context=NULL;
      sleep(2);
      goto start_ws;
    }
  }
  
  lws_context_destroy(context);
  pthread_join(whois_thread, NULL);
  return 0;
}
