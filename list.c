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
} *v4;
struct v6 {
  uint64_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
} *v6;
uint32_t nv4,nv6;

int cmp_v4(struct v4 *x,struct v4 *y){
  if (x->ip>y->ip)return 1;
  if (x->ip<y->ip)return -1;
  if (x->cidr>y->cidr)return 1;
  if (x->cidr<y->cidr)return -1;
  return 0;
}

int main(){
  uint32_t i,j,q,c4[33],c6[129],ip4;
  uint8_t a[4];
  FILE *fp;
  
  fp=fopen(BGPFILE,"rb");
  if(fp==NULL)exit(0);
  fread(&nv4,4,1,fp);
  fread(&nv6,4,1,fp);
  v4=(struct v4 *)malloc(nv4*sizeof(struct v4));
  if(v4==NULL)exit(0);
  v6=(struct v6 *)malloc(nv6*sizeof(struct v6));
  if(v6==NULL)exit(0);
  fread(v4,sizeof(struct v4),nv4,fp);
  qsort(v4,nv4,sizeof(struct v4),cmp_v4);
  fread(v6,sizeof(struct v6),nv6,fp);
  fclose(fp);
  
  printf("run %lu %lu\n",nv4,nv6);

  for(i=0;i<33;i++)c4[i]=0;
  for(i=0;i<nv4;i++)c4[v4[i].cidr]++;
  fp=fopen(V4FILE,"wt");
  fprintf(fp,"# v4_tot: %lu\n",nv4);
  for(i=0;i<33;i++)if(c4[i]>0)fprintf(fp,"# v4_cidr%d: %lu\n",i,c4[i]);
  for(i=0;i<nv4;i++){
    for(ip4=v4[i].ip,j=0;j<4;j++){a[j]=ip4&0xff; ip4>>=8;}
    fprintf(fp,"%d.%d.%d.%d",a[3],a[2],a[1],a[0]);
    fprintf(fp,"/%d,%lu\n",v4[i].cidr,v4[i].asn);
  }
  fclose(fp);

  
}
