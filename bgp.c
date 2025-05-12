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

// Scrive frame WebSocket
void write_frame(SSL *ssl, const char *msg) {
    size_t len = strlen(msg);
    unsigned char header[10];
    int hlen = 0;

    header[0] = 0x81; // FIN + text
    if (len < 126) {
        header[1] = len;
        hlen = 2;
    } else {
        header[1] = 126;
        header[2] = (len >> 8) & 0xFF;
        header[3] = len & 0xFF;
        hlen = 4;
    }

    SSL_write(ssl, header, hlen);
    SSL_write(ssl, msg, len);
}

int main() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int sockfd,n;
  struct hostent *server;
  struct sockaddr_in serv_addr = {0};
  char buffer[2048];
  const char *data="{"
    "\"type\": \"ris_subscribe\","
    "\"data\": {\"host\": \"rrc00\","
    "\"moreSpecific\": \"true\" }"
  "}";
  const chat *header=
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
  
  printf("1\n");
  SSL_write(ssl,header,strlen(header));
  printf("2\n");
  SSL_read(ssl,buffer,2048);
  printf("3\n");
  SSL_write(ssl,data,strlen(data));
  printf("4\n");

  for(;;){
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
