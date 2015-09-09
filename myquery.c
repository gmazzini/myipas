// UDP client ver 0.02 by GM

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

int main(){
	int sockfd,n;
	struct sockaddr_in servaddr;
	char recvline[100],ip[100];
	
	sockfd=socket(AF_INET,SOCK_DGRAM,0);
	bzero((char *)&servaddr,sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr=inet_addr("127.0.0.1");
	servaddr.sin_port=htons(5555);
	
	for(;;){
		scanf("%s",ip);
		if(feof(stdin))break;
		sendto(sockfd,ip,strlen(ip),0,(struct sockaddr *)&servaddr,sizeof(servaddr));
		n=recvfrom(sockfd,recvline,100,0,NULL,NULL);
		recvline[n]=0;
		printf("%s",recvline);
	}
	close(sockfd);
}
