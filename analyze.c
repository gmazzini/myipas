#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#define BGPFILE "/home/www/fulltable/bgp.raw"
#define ASN 200000 

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
    uint32_t v4[17]; // 8 to 24
    uint32_t v6[33];   // 16 to 48
  } *stat;
  uint64_t totv4,totv6;
  uint8_t j;
  FILE *fp;
  uint32_t i,vv[100],nv4,nv6;
  time_t tr;

  stat=(struct stat *)malloc(ASN*sizeof(struct stat));
  if(stat==NULL)exit(0);
  for(i=0;i<ASN;i++){
    for(j=0;j<17;j++)stat[i].v4[j]=0;
    for(j=0;j<33;j++)stat[i].v6[j]=0;
  }
  for(i=0;i<100;i++)vv[i]=0;
  tr=time(NULL);
  fp=fopen(BGPFILE,"rb");
  if(fp==NULL)exit(0);
  fread(&nv4,4,1,fp);
  fread(&nv6,4,1,fp);
  for(i=0;i<nv4;i++){
    fread(&v4,sizeof(struct v4),1,fp);
    if(v4.asn==0||v4.cidr<8||v4.cidr>24||v4.asn>=ASN)continue;
    vv[(tr-v4.ts)/86400]++;
    stat[v4.asn].v4[v4.cidr-8]++;
  }
  for(i=0;i<nv6;i++){
    fread(&v6,sizeof(struct v6),1,fp);
    if(v6.asn==0||v6.cidr<16||v6.cidr>48||v6.asn>=ASN)continue;
    vv[(tr-v6.ts)/86400]++;
    stat[v6.asn].v6[v6.cidr-16]++;
  }
  fclose(fp);

  for(i=0;i<100;i++)printf("dd:%lu %llu\n",i,vv[i]);
  for(i=0;i<ASN;i++){
    for(totv4=0,j=8;j<=24;j++)totv4+=stat[i].v4[j]*(1UL<<(32-j));
    for(totv6=0,j=16;j<=48;j++)totv6+=stat[i].v6[j]*(1UL<<(128-j));
    if(totv4==0&&totv6==0)continue;
    printf("asn:%lu",i);
    printf(" v4:%llu",totv4); for(j=0;j<17;j++)printf(",%lu",stat[i].v4[j]);
    printf(" v6:%llu",totv6); for(j=0;j<33;j++)printf(",%lu",stat[i].v6[j]);
    printf("\n");
  }  
}
