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
long rlmv4,elmv6,elm;

int main(){
  struct v4 v4;
  struct v6 v6;
  

}
