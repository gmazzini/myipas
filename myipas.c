// myipas 2015-16 by GM
// changelog (appears on github since v0.03)
// v0.04 change of FILENETS repository
// v0.05 thread implementation and dns query

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>

#define BUFMSG 10000
#define NTHREAD 256
#define LISTENPORT 5555
#define TOTNETS 1000000
#define MAXSTEPS 40
#define FILENETS "/myipas/asn3.txt"

struct ipas_class {
	unsigned long ipv4;
	short int cidr;
	unsigned long as;
};
struct arg_pass {
	char *mesg;
	int lenmesg;
	struct sockaddr_in cliaddr;
};

pthread_t *tid;
int sockfd;
struct ipas_class *myipasclass=NULL;
unsigned long mymask[33];
unsigned long totipasclass,totallquery,totmalformed;

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

void *manage(void *arg_void){
	struct arg_pass *myarg=(struct arg_pass *)arg_void;
	int lenrecv,i,j,ml,lenaux,lenanswer,mystop;
	long myclass;
	unsigned int query;
	unsigned long asret;
	unsigned long ipsrcaddr;
	struct sockaddr_in netip;
	char *recv,*auxbuf,*dominio,*aux1,*aux2;
	
	recv=(char *)malloc(BUFMSG*sizeof(char));
	auxbuf=(char *)malloc(BUFMSG*sizeof(char));
	dominio=(char *)malloc(BUFMSG*sizeof(char));
	
	// check query header
	mystop=0;
	// QR B2 b7
	if(!mystop && ((*(myarg->mesg+2))&0b10000000)!=0){mystop=1; totmalformed++; }
	// AA B2 b2
	if(!mystop && ((*(myarg->mesg+2))&0b00000100)!=0){mystop=1; totmalformed++; }
	// Z B3 b6
	if(!mystop && ((*(myarg->mesg+3))&0b01000000)!=0){mystop=1; totmalformed++; }
	// Rcode B3 b3-0
	if(!mystop && ((*(myarg->mesg+3))&0b00001111)!=0){mystop=1; totmalformed++; }
	// Total Answer B6 B7
	if(!mystop && (*(myarg->mesg+6))!=0){mystop=1; totmalformed++; }
	if(!mystop && (*(myarg->mesg+7))!=0){mystop=1; totmalformed++; }
	
	prinf("mystop:%d\n",mystop); fflush(stdout);
	
	// domain name analisys
	if(!mystop){
		lenanswer=0;
		for(i=0,aux1=dominio,aux2=myarg->mesg+12;;){
			ml=(int)*aux2;
			if(ml==0)break;
			aux2++;
			i+=ml;
			if(i>=BUFMSG){mystop=1; totmalformed++; break;}
			for(j=0;j<ml;j++)*aux1++=tolower(*aux2++);
			i++;
			if(i>=BUFMSG){mystop=1; totmalformed++; break;}
			*aux1++='.';
			lenanswer+=ml+1;
		}
		if(i==0)*aux1='\0';
		else *(--aux1)='\0';
	}
	
	// request analisys
	if(!mystop){
		totallquery++;
		
		// query type
		query=*(aux2+2);
		lenanswer+=5;
		
		printf("query:%d\n",query); fflush(stdout);
		
		// command processing
		if(query==16 && strncmp(dominio,"cmd",3)==0){
			printf("%s\n",dominio); fflush(stdout);
			
			for(aux1=dominio;*aux1!='\0';aux1++)if(*aux1=='/')break;
			if(*aux1=='\0')sprintf(auxbuf,"request malfomed");
			else {
				for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
				if(*aux1=='\0')sprintf(auxbuf,"missed command");
				else {
					*aux1='\0';
					// reload configuration
					if(strcmp(aux2,"reload")==0){
						sprintf(auxbuf,"configuration reloaded");
					}
					// ipas
					else if(strcmp(aux2,"ipas")==0){
						for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
						if(*aux1=='\0')sprintf(auxbuf,"missed source IP");
						else {
							*aux1='\0';
							inet_pton(AF_INET,aux2,&(netip.sin_addr));
							ipsrcaddr=ntohl(netip.sin_addr.s_addr);
							for(i=32;i>=8;i--){
								myclass=myipsearch(ipsrcaddr&mymask[i]);
								if(myclass!=-1)break;
							}
							if(myclass>=0)asret=myipasclass[myclass].as;
							else asret=0;
							sprintf(auxbuf,"%ld %s",asret,aux2);
						}
					}
					// unknown
					else sprintf(auxbuf,"command unknown");
				}
				
			}
			lenaux=strlen(auxbuf);
			lenrecv=12+lenanswer+13+lenaux;
			if(lenrecv<BUFMSG){
				recv[0]=*myarg->mesg; recv[1]=*(myarg->mesg+1); recv[2]=129; recv[3]=128; recv[4]=*(myarg->mesg+4); recv[5]=*(myarg->mesg+5); recv[6]=0; recv[7]=1; recv[8]=0; recv[9]=0; recv[10]=0; recv[11]=0;
				memcpy(recv+12,myarg->mesg+12,lenanswer);
				aux1=recv+12+lenanswer;
				aux1[0]=192; aux1[1]=12; aux1[2]=0; aux1[3]=16; aux1[4]=0; aux1[5]=1; aux1[6]=0; aux1[7]=0; aux1[8]=14; aux1[9]=16; aux1[10]=0; aux1[12]=lenaux; aux1[11]=aux1[12]+1;
				memcpy(aux1+13,auxbuf,lenaux);
			}
		}
		
		// answer
		sendto(sockfd,recv,lenrecv,0,(struct sockaddr *)&myarg->cliaddr,sizeof(myarg->cliaddr));
	}
	
	free(recv);
	free(auxbuf);
	free(dominio);
	return NULL;
}

int main(int argc, char**argv){
	struct arg_pass *myargs;
	int i,j;
	socklen_t len;
	FILE *fp;
	struct sockaddr_in netip,servaddr;
	char buf[BUFMSG];
	
	// initialization
	for(i=0;i<=32;i++)mymask[i]=~((1<<(32-i))-1);
	myipasclass=(struct ipas_class *)malloc(TOTNETS*sizeof(struct ipas_class));
	tid=(pthread_t *)malloc(NTHREAD*sizeof(pthread_t));
	myargs=(struct arg_pass *)malloc(NTHREAD*sizeof(struct arg_pass));
	for(i=0;i<NTHREAD;i++)myargs[i].mesg=(char *)malloc(BUFMSG*sizeof(char));
	
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
	
	// bindind
	sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	memset((char *)&servaddr,0,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(LISTENPORT);
	bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
	len=sizeof(struct sockaddr_in);
	
	printf("binding up...\n"); fflush(stdout);
	
	for(j=0;;){
		// receive request and launch a processing thread
		myargs[j].lenmesg=recvfrom(sockfd,myargs[j].mesg,BUFMSG,0,(struct sockaddr *)&myargs[j].cliaddr,&len);
		pthread_create(&(tid[j]),NULL,&manage,&myargs[j]);
		pthread_detach(tid[j]);
		if(++j==NTHREAD)j=0;
	}
	
}
