#include <stdio.h>
#include <stdint.h>
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
  long start,end,pos;
  uint8_t found;
  
  if(elm==0){
    pos=0;
    elm=1;
  }
  else {
    start=0;
    end=elm-1;
    found=0;
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
  stat[pos].asn=asn;
  if(v6)stat[pos].v6[cidr]++;
  else stat[pos].v4[cidr]++;
}

int main(){
  struct v4 v4;
  struct v6 v6;
  long i;

  stat=(struct stat *)calloc(ASNELM*sizeof(struct stat));
  if(stat==NULL)exit(0);
  fp=fopen(BKP4FILE,"rb");
  if(fp==NULL)exit(0);
  fread(&elmv4,4,1,fp);
  for(i=0;i<elmv4;i++){
    fread(&v4,sizeof(struct v4),1,fp);
    myadd(0,v4.asn,v4.cidr);
  }
  fclose(fp);
  fp=fopen(BKP6FILE,"rb");
  if(fp==NULL)exit(0);
  fread(&elmv6,4,1,fp);
  for(i=0;i<elmv6;i++){
    fread(&v6,sizeof(struct v6),1,fp);
    myadd(1,v6.asn,v6.cidr);
  }
  fclose(fp);

  printf("%lu\n",elm);
  
}
