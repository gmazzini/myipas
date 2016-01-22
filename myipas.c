// myipas 2015-16 by GM
// changelog (appears on github since v0.03)
// v0.04 change of FILENETS repository

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>

#define BUFMSG 128
#define LISTENPORT 5555
#define TOTNETS 1000000
#define MAXSTEPS 40
#define FILENETS "/myipas/asn3.txt"

struct ipas_class {
	unsigned long ipv4;
	short int cidr;
	unsigned long as;
};

int sockfd;
struct ipas_class *myipasclass=NULL;
unsigned long mymask[33];
unsigned long totipasclass;

// comparison function
static int myipcmp(const void *p1, const void *p2){
	long ret;
	ret=((struct ipas_class *)p1)->ipv4-((struct ipas_class*)p2)->ipv4;
	if(ret==0)return 0;
	return (ret>0)?1:-1;
}

// Binary search with maximum steps for ipclass search
long myipsearch(unsigned long ip_tocheck){
	long zinit,zend,myclass;
	unsigned long ip_mask;
	int i;
	
	zinit=0;
	zend=totipasclass-1;
	for(i=0;i<MAXSTEPS;i++){
		myclass=(zinit+zend)/2;
		ip_mask=mymask[myipasclass[myclass].cidr];
		if((ip_tocheck&ip_mask)==myipasclass[myclass].ipv4)break;
		if((ip_tocheck&ip_mask)>myipasclass[myclass].ipv4)zinit=myclass+1;
		else zend=myclass-1;
		if(zinit>zend||zinit>=totipasclass||zend<0)return -1;
	}
	return myclass;
}

int main(int argc, char**argv){
	int i,lenmesg;
	socklen_t len;
	FILE *fp;
	struct sockaddr_in netip,servaddr,cliaddr;
	char buf[BUFMSG],mesg[BUFMSG];
	unsigned long iplook;
	long myclass;
	unsigned long asret;
	
	// initialization
	for(i=0;i<=32;i++)mymask[i]=~((1<<(32-i))-1);
	myipasclass=(struct ipas_class *)malloc(TOTNETS*sizeof(struct ipas_class));
	
	// read data
	fp=fopen(FILENETS,"rt");
	for(totipasclass=0;;){
		fscanf(fp,"%s %hu %lu",buf,&myipasclass[totipasclass].cidr,&myipasclass[totipasclass].as);
		if(feof(fp))break;
		inet_pton(AF_INET,buf,&(netip.sin_addr));
		myipasclass[totipasclass].ipv4=ntohl(netip.sin_addr.s_addr)&mymask[myipasclass[totipasclass].cidr];
		totipasclass++;
	}
	fclose(fp);
	qsort(myipasclass,totipasclass,sizeof(struct ipas_class),myipcmp);
	
	printf("running...\n"); fflush(stdout);
	
	// bindind
	sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	memset((char *)&servaddr,0,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(LISTENPORT);
	bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
	len=sizeof(struct sockaddr_in);
	
	for(;;){
		// receive request and launch a processing thread
		lenmesg=recvfrom(sockfd,mesg,BUFMSG,0,(struct sockaddr *)&cliaddr,&len);
		*(mesg+lenmesg)='\0';
		inet_pton(AF_INET,mesg,&(netip.sin_addr));
		iplook=ntohl(netip.sin_addr.s_addr);
		for(i=32;i>=8;i--){
			myclass=myipsearch(iplook&mymask[i]);
			if(myclass!=-1)break;
		}
		if(myclass>=0)asret=myipasclass[myclass].as;
		else asret=0;
		sprintf(buf,"%ld %s\n",asret,mesg);
		sendto(sockfd,buf,strlen(buf),0,(struct sockaddr *)&cliaddr,sizeof(cliaddr));
	}
}
