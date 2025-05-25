#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#define BKP4FILE "/home/www/fulltable/bkp4.raw"
#define BKP6FILE "/home/www/fulltable/bkp6.raw"
#define ASNELM 1000000

struct v4 {
  uint32_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
};
struct v6 {
  uint64_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
};
struct stat {
  uint32_t asn;
  uint32_t v4[33];
  uint32_t v6[129];
} *stat;
long elmv4,elmv6,elm;

void myadd(uint8_t v6,uint32_t asn,uint8_t cidr){
  long start,end,pos,i;
  uint8_t found,j;

  found=0;
  if(elm==0){
    pos=0;
    elm=1;
  }
  else {
    start=0;
    end=elm-1;
    while(start<=end){
      pos=start+(end-start)/2;
      if(asn==stat[pos].asn){found=1; break;}
      else if(asn>stat[pos].asn)start=pos+1;
      else end=pos-1;
    }
    if(!found){
      if(elm>=ASNELM)exit(0);
      pos=start;
      for(i=elm;i>pos;i--)stat[i]=stat[i-1];
      elm++;
    }
  }
  if(!found){
    for(j=0;j<33;j++)stat[pos].v4[j]=0;
    for(j=0;j<129;j++)stat[pos].v6[j]=0;
    stat[pos].asn=asn;
  }
  if(v6)stat[pos].v6[cidr]++;
  else stat[pos].v4[cidr]++;
}

int main(){
  struct v4 *v4;
  struct v6 *v6;
  uint64_t tot;
  long i;
  uint8_t j;
  FILE *fp;
  uint32_t vv[1000],ct;
  time_t tr;

  stat=(struct stat *)malloc(ASNELM*sizeof(struct stat));
  if(stat==NULL)exit(0);

  for(i=0;i<1000;i++)vv[i]=0;
  tr=time(NULL);
  
  fp=fopen(BKP4FILE,"rb");
  if(fp==NULL)exit(0);
  fread(&elmv4,4,1,fp);
  v4=(struct v4 *)malloc(elmv4*sizeof(struct v4));
  if(v4==NULL)exit(0);
  fread(v4,sizeof(struct v4),elmv4,fp);
  fclose(fp);
  for(i=0;i<elmv4;i++){
    vv[(tr-v4[i].ts)/3600]++;
    myadd(0,v4[i].asn,v4[i].cidr);
  }
  free(v4);
  
  fp=fopen(BKP6FILE,"rb");
  if(fp==NULL)exit(0);
  fread(&elmv6,4,1,fp);
  v6=(struct v6 *)malloc(elmv6*sizeof(struct v6));
  if(v6==NULL)exit(0);
  fread(v6,sizeof(struct v6),elmv6,fp);
  fclose(fp);
  for(i=0;i<elmv6;i++){
    vv[(tr-v6[i].ts)/3600]++;
    myadd(1,v6[i].asn,v6[i].cidr);
  }
  free(v6);

  for(i=0;i<elm;i++){
    printf("asn:%lu\n",stat[i].asn);
    for(tot=0,j=8;j<=24;j++)tot+=stat[i].v4[j]*(1UL<<(32-j));
    printf("v4:%llu:",tot);
    for(j=8;j<=24;j++)printf("%lu ",stat[i].v4[j]);
    for(tot=0,j=16;j<=48;j++)tot+=stat[i].v6[j]*(1UL<<(128-j));
    printf("\nv6:%llu:",tot);
    for(j=16;j<=48;j++)printf("%lu ",stat[i].v6[j]);
    printf("\n--\n");
  }
  for(i=0;i<1000;i++)printf("%lu %llu\n",i,vv[i]);
  
}
