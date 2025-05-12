// da rivedereeeeeeeee


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOST "ris-live.ripe.net"
#define PORT 443
#define WS_KEY "dGhlIHNhbXBsZSBub25jZQ=="

volatile sig_atomic_t dump_ipv4 = 0;
volatile sig_atomic_t dump_ipv6 = 0;

// Semplici array per archiviare prefissi IP e ASN
char *ip4[1000];
char *ip6[1000];
int ip4_count = 0, ip6_count = 0;

void handle_signal(int sig){
  if(sig==SIGUSR1)dump_ipv4=1;
  else if(sig==SIGUSR2)dump_ipv6=1;
}

int main() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int sockfd,n,i;
  struct hostent *server;
  struct sockaddr_in serv_addr = {0};
  char buffer[2048];
  uint8_t hh[6],mm[200],len,mb[4];
  uint32_t mask;
  
  const char *data="{"
    "\"type\": \"ris_subscribe\","
    "\"data\": {\"host\": \"rrc00\","
    "\"moreSpecific\": \"true\" }"
  "}";
  const char *header=
    "GET /v1/ws/?client=gm1 HTTP/1.1\r\n"
    "Host: rrc14.ripe.net\r\n"
    "Accept: */*\r\n"
    "Connection: Upgrade\r\n"
    "Upgrade: websocket\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "\r\n";

  signal(SIGUSR1,handle_signal);
  signal(SIGUSR2,handle_signal);
    
  SSL_library_init();
  SSL_load_error_strings();
  method=TLS_client_method();
  ctx=SSL_CTX_new(method);
  sockfd=socket(AF_INET,SOCK_STREAM,0);
  server=gethostbyname(HOST);
  serv_addr.sin_family=AF_INET;
  serv_addr.sin_port=htons(PORT);
  memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
  connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr));
  ssl=SSL_new(ctx);
  SSL_set_fd(ssl,sockfd);
  SSL_connect(ssl);
  
  SSL_write(ssl,header,strlen(header));
  n=SSL_read(ssl,buffer,2048);
  len=strlen(data);
  hh[0]=0x81;
  hh[1]=0x80 | (uint8_t)strlen(data);
  mask=rand() & 0x7FFFFFFF;
  mb[0]=(mask>>24)&0xFF;
  mb[1]=(mask>>16)&0xFF;
  mb[2]=(mask>>8)&0xFF;
  mb[3]=mask&0xFF;
  memcpy(hh+2,mb,4);
  for(i=0;i<len;i++)mm[i]=data[i]^mb[i%4];
  SSL_write(ssl,hh,6);
  SSL_write(ssl,mm,len);
  
  for(;;){

    char buffer[2048];
    uint8_t hh[6],mm[200],len,mb[4],opcode,final,masked,ext[8];
    uint32_t mask;
    uint64_t payload_len;



    SSL_read(ssl,hdr,2);
    opcode=hh[0]&0x0F;
    final=hh[0]&0x80;
    masked=hh[1]&0x80;
    payload_len=hdr[1]&0x7F;
    if(payload_len==126){
      SSL_read(ssl,ext,2);
      payload_len=(ext[0]<<8)|ext[1];
    } else if (payload_len==127){
      SSL_read(ssl,ext,8);
      payload_len=0;
      for(i=0;i<8;i++)payload_len=(payload_len << 8)|ext[i];
    }
    if(masked)SSL_read(ssl,mb,4);

    buf=malloc(payload_len);
    SSL_read(ssl,buf,payload_len);
 <= 

    if(opcode == 0x9) {
        // Respond with PONG
        uint8_t pong[6] = {0x8A, 0x80};  // FIN + PONG + no payload
        pong[2] = pong[3] = pong[4] = pong[5] = 0;
        SSL_write(ssl, pong, 6);
        free(payload);
        return 0;
    }

    if (masked) {
        for (uint64_t i = 0; i < payload_len; i++) {
            payload[i] ^= mask[i % 4];
        }
    }

    size_t copy_len = (payload_len < maxlen - 1) ? payload_len : maxlen - 1;
    memcpy(out, payload, copy_len);
    out[copy_len] = '\0';

    free(payload);
    return copy_len;





    
    n=SSL_read(ssl,buffer,2048);
    buffer[n]='\0';
    printf("%s",buffer);


    /*
        if (strstr(buffer, "announcements")) {
            if (strstr(buffer, ":")) {
                ip6[ip6_count++] = strdup(buffer); // esempio
            } else {
                ip4[ip4_count++] = strdup(buffer); // esempio
            }
        }

        if (dump_ipv4) {
            FILE *f = fopen("ip4.txt", "w");
            for (int i = 0; i < ip4_count; ++i)
                fprintf(f, "%s\n", ip4[i]);
            fclose(f);
            dump_ipv4 = 0;
        }
        if (dump_ipv6) {
            FILE *f = fopen("ip6.txt", "w");
            for (int i = 0; i < ip6_count; ++i)
                fprintf(f, "%s\n", ip6[i]);
            fclose(f);
            dump_ipv6 = 0;
        }

      */
      


      
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}
