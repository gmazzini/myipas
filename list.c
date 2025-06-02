#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#define V4FILE "/home/www/fulltable/m4.txt"
#define V6FILE "/home/www/fulltable/m6.txt"
#define BGPFILE "/home/www/fulltable/bgp.raw"
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
uint32_t nv4,nv6;

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

int main(){
  uint32_t i,j,q,c4[33],c6[129],ip4;
  uint8_t a[4];
  struct v4 av4;
  struct v6 av6;
  FILE *fp;
  
  v4=(struct v4 **)malloc(HASHELM*sizeof(struct v4 *));
  if(v4==NULL)exit(0);
  for(i=0;i<HASHELM;i++)v4[i]=NULL;
  v6=(struct v6 **)malloc(HASHELM*sizeof(struct v6 *));
  if(v6==NULL)exit(0);
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

      printf("run %lu %lu\n",nv4,nv6);

  for(i=0;i<33;i++)c4[i]=0;
  for(i=0;i<nv4;i++)c4[v4[j]->cidr]++;
  fp=fopen(V4FILE,"wt");
  fprintf(fp,"# v4_tot: %lu\n",nv4);
  for(i=0;i<33;i++)if(c4[i]>0)fprintf(fp,"# v4_cidr%d: %lu\n",i,c4[i]);
  for(i=0;i<nv4;i++){
    for(ip4=v4[i]->ip,j=0;j<4;j++){a[j]=ip4&0xff; ip4>>=8;}
    fprintf(fp,"%d.%d.%d.%d",a[3],a[2],a[1],a[0]);
    fprintf(fp,"/%d,%lu\n",v4[i]->cidr,v4[i]->asn);
  }
  fclose(fp);

  
}
