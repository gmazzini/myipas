#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#define V4FILE "/home/www/fulltable/m4.txt"
#define V6FILE "/home/www/fulltable/m6.txt"
#define BGPFILE "/home/www/fulltable/bgp.raw"

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

int cmp_v4(const void *a, const void *b){
  struct v4 *x = (struct v4 *)a;
  struct v4 *y = (struct v4 *)b;
  if (x->ip>y->ip)return 1;
  if (x->ip<y->ip)return -1;
  if (x->cidr>y->cidr)return 1;
  if (x->cidr<y->cidr)return -1;
  return 0;
}

int cmp_v6(const void *a, const void *b){
  struct v6 *x = (struct v6 *)a;
  struct v6 *y = (struct v6 *)b;
  if (x->ip>y->ip)return 1;
  if (x->ip<y->ip)return -1;
  if (x->cidr>y->cidr)return 1;
  if (x->cidr<y->cidr)return -1;
  return 0;
}

int main(){
  uint32_t i,j,q,c4[33],c6[129],ip4,nv4,nv6,anv4,anv6;
  uint8_t a[4];
  uint16_t b[4];
  uint64_t ip6;
  FILE *fp;
  struct v4 *v4;
  struct v6 *v6;
  
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
  qsort(v6,nv6,sizeof(struct v6),cmp_v6);
  fclose(fp);
  
  printf("run %lu %lu\n",nv4,nv6);

  for(i=0;i<33;i++)c4[i]=0;
  for(anv4=0,i=0;i<nv4;i++)if(v4[i].cidr>0&&v4[i].asn>0){c4[v4[i].cidr]++; anv4++;}
  fp=fopen(V4FILE,"wt");
  fprintf(fp,"# v4_tot: %lu\n",anv4);
  for(i=0;i<33;i++)if(c4[i]>0)fprintf(fp,"# v4_cidr%d: %lu\n",i,c4[i]);
  for(i=0;i<nv4;i++){
    if(v4[i].cidr==0||v4[i].asn==0)continue;
    for(ip4=v4[i].ip,j=0;j<4;j++){a[j]=ip4&0xff; ip4>>=8;}
    fprintf(fp,"%d.%d.%d.%d",a[3],a[2],a[1],a[0]);
    fprintf(fp,"/%d,%lu\n",v4[i].cidr,v4[i].asn);
  }
  fclose(fp);
  for(i=0;i<129;i++)c6[i]=0;
  for(anv6=0,i=0;i<nv6;i++)if(v6[i].cidr>0&&v6[i].asn>0){c6[v6[i].cidr]++; anv6++;}
  fp=fopen(V6FILE,"wt");
  fprintf(fp,"# v6_tot: %lu\n",nv6);
  for(i=0;i<129;i++)if(c6[i]>0)fprintf(fp,"# v6_cidr%d: %lu\n",i,c6[i]);
  for(i=0;i<nv6;i++){
    f(v6[i].cidr==0||v6[i].asn==0)continue;
    for(ip6=v6[i].ip,q=0;q<64;q++)if(ip6&1)break; else ip6>>=1;
    for(ip6=v6[i].ip,j=0;j<4;j++){b[j]=ip6&0xffff; ip6>>=16;}
    if(q>=48)fprintf(fp,"%x::",b[3]);
    else if(q>=32)fprintf(fp,"%x:%x::",b[3],b[2]);
    else if(q>=16)fprintf(fp,"%x:%x:%x::",b[3],b[2],b[1]);
    else fprintf(fp,"%x:%x:%x:%x::",b[3],b[2],b[1],b[0]);
    fprintf(fp,"/%d,%lu\n",v6[i].cidr,v6[i].asn);
  }
  fclose(fp);
  
}
