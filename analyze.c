#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#define BKP4FILE "/home/www/fulltable/bkp4.raw"
#define BKP6FILE "/home/www/fulltable/bkp6.raw"
#define HASHELM 16777216

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
      if(elm>=100000)exit(0);
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


uint32_t myhash(uint32_t asn,uint8_t cidr){
    uint64_t mix=((uint64_t)asn<<8)|cidr;
    mix^=mix>>33;
    mix*=0xff51afd7ed558ccdULL;
    mix^=mix>>33;
    mix*=0xc4ceb9fe1a85ec53ULL;
    mix^=mix>>33;
    return (uint32_t)(mix&0x00FFFFFF);
}

int main(){
  struct v4 v4;
  struct v6 v6;
  struct stat **ptr;
  uint64_t tot;
  uint8_t j;
  FILE *fp;
  uint32_t i,vv[100],q;
  time_t tr;

  ptr=(struct stat **)malloc(HASHELM*sizeof(struct stat *));
  if(ptr==NULL)exit(0);
  for(i=0;i<HASHELM*sizeof(struct stat *);i++)ptr[i]=NULL;
  for(i=0;i<100;i++)vv[i]=0;
  tr=time(NULL);
  
  fp=fopen(BKP4FILE,"rb");
  if(fp==NULL)exit(0);
  fread(&elmv4,4,1,fp);
  for(i=0;i<elmv4;i++){
    fread(&v4,sizeof(struct v4),1,fp);
    vv[(tr-v4.ts)/86400]++;
    q=myhash(v4.asn,v4.cidr);



    
   // myadd(0,v4.asn,v4.cidr);
  }
  fclose(fp);
  for(i=0;i<100;i++)printf("dd:%lu %llu\n",i,vv[i]);
  for(i=0;i<(1UL<<24);i++)j=1;
exit(0);
   
  fp=fopen(BKP6FILE,"rb");
  if(fp==NULL)exit(0);
  fread(&elmv6,4,1,fp);
  for(i=0;i<elmv6;i++){
    fread(&v6,sizeof(struct v6),1,fp);
    vv[(tr-v6.ts)/86400]++;
    myadd(1,v6.asn,v6.cidr);
  }
  fclose(fp);

  for(i=0;i<elm;i++){
    printf("asn:%lu",stat[i].asn);
    for(tot=0,j=8;j<=24;j++)tot+=stat[i].v4[j]*(1UL<<(32-j));
    printf(" v4:%llu",tot);
    for(j=8;j<=24;j++)printf(",%lu",stat[i].v4[j]);
    for(tot=0,j=16;j<=48;j++)tot+=stat[i].v6[j]*(1UL<<(128-j));
    printf(" v6:%llu",tot);
    for(j=16;j<=48;j++)printf(",%lu",stat[i].v6[j]);
    printf("\n");
  }
  for(i=0;i<100;i++)printf("dd:%lu %llu\n",i,vv[i]);
  
}
