#define BKP4FILE "/home/www/fulltable/bkp4.raw"
#define BKP6FILE "/home/www/fulltable/bkp6.raw"

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
};
long elmv4,elmv6,elm;

int main(){
  struct v4 v4;
  struct v6 v6;
  long i;

  fp=fopen(BKP4FILE,"rb");
  if(fp==NULL)exit(0);
  fread(&elmv4,4,1,fp);
  for(i=0;i<elmv4;i++){
    fread(&v4,sizeof(struct v4),1,fp);
  }
  fclose(fp);
  
  fp=fopen(BKP6FILE,"rb");
  if(fp!=NULL){
    fread(&elmv6,4,1,fp);
    fread(v6,sizeof(struct v6),elmv6,fp);
    fclose(fp);
  }
  

}
