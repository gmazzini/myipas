#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#define BKP4FILE "/home/www/fulltable/bkp4.raw"
#define BKP6FILE "/home/www/fulltable/bkp6.raw"
#define HASHELM 16777216

uint32_t myhash(uint32_t asn){
  uint32_t x=asn;
  x^=x>>16;
  x*=0x85ebca6b;
  x^=x>>13;
  x*=0xc2b2ae35;
  x^=x>>16;
  return x&0x00FFFFFF;
}

int main(){
  struct v4 {
    uint32_t ip;
    uint8_t cidr;
    uint32_t asn;
    uint32_t ts;
  } v4;
  struct v6 {
    uint64_t ip;
    uint8_t cidr;
    uint32_t asn;
    uint32_t ts;
  } v6;
  struct stat {
    uint32_t asn;
    uint32_t v4[33];
    uint32_t v6[129];
  } **ptr;
  uint64_t tot;
  uint8_t j;
  FILE *fp;
  uint32_t i,vv[100],q,elmv4,elmv6,elm;
  time_t tr;

  ptr=(struct stat **)malloc(HASHELM*sizeof(struct stat *));
  if(ptr==NULL)exit(0);
  for(i=0;i<HASHELM;i++)ptr[i]=NULL;
  for(i=0;i<100;i++)vv[i]=0;
  tr=time(NULL);
  
  fp=fopen(BKP4FILE,"rb");
  if(fp==NULL)exit(0);
  fread(&elmv4,4,1,fp);
  for(i=0;i<elmv4;i++){
    fread(&v4,sizeof(struct v4),1,fp);
    vv[(tr-v4.ts)/86400]++;
    q=myhash(v4.asn);
    if(ptr[q]==NULL){
      ptr[q]=(struct stat *)malloc(sizeof(struct stat));
      if(ptr[q]==NULL)exit(0);
      for(j=0;j<33;j++)ptr[q]->v4[j]=0;
      for(j=0;j<129;j++)ptr[q]->v6[j]=0;
      ptr[q]->asn=v4.asn;
    }
    ptr[q]->v4[v4.cidr]++;
  }
  fclose(fp);

  for(i=0;i<10;i++)printf("dd:%lu %llu\n",i,vv[i]);
  for(i=0;i<HASHELM;i++)if(ptr[i]!=NULL){
    printf("asn:%lu",ptr[i]->asn);
    for(tot=0,j=8;j<=24;j++)tot+=ptr[i]->v4[j]*(1UL<<(32-j));
    printf(" v4:%llu",tot);
    for(j=8;j<=24;j++)printf(",%lu",ptr[i]->v4[j]);
    printf("\n");

  }
exit(0);
   
 /*
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
*/
  
}
