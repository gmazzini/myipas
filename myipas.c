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

void *manage(void *arg_void){
	struct arg_pass *myarg=(struct arg_pass *)arg_void;
	int sockreq,lenrecv,i,j,ml,lenaux,lenanswer,wlok,blok,cblok,mystop,ret;
	long myclass,mystatus;
	unsigned int query;
	unsigned long ipidx;
	unsigned long ipsrcaddr,ipprofaddr,ip_tocheck,ipclassaddr;
	struct sockaddr_in reqaddr,netip;
	struct sockaddr_in6 reqaddr6;
	char *recv,*auxbuf,*dominio,*aux1,*aux2,ipbuf[30];
	time_t curtime;
	struct tm *loctime;
	double myuptime;
	struct timeval tv;
	
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
	
	// define the ip to check to implement the profiled port
	if(!mystop){
		ip_tocheck=ntohl(myarg->cliaddr.sin_addr.s_addr);
		if((ip_tocheck&IPMASK12)==IPCLASS){
			ipidx=ip_tocheck-IPCLASS;
			if(myprofile[ipidx]!=0)ip_tocheck=myprofile[ipidx];
		}
	}
	
	// define the filter class
	if(!mystop){
		myclass=myipsearch(ip_tocheck);
		if(myclass==-1){mystop=1; totoutscope++; }
	}
	
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
		myipclass[myclass].totquery++;
		totallquery++;
		
		// query type
		query=*(aux2+2);
		lenanswer+=5;
		
		// command processing
		if(query==16 && strncmp(dominio,"cmd",3)==0){
			for(aux1=dominio;*aux1!='\0';aux1++)if(*aux1=='/')break;
			if(*aux1=='\0')sprintf(auxbuf,"request malfomed");
			else {
				for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
				if(*aux1=='\0')sprintf(auxbuf,"missed password");
				else {
					*aux1='\0';
					if(strcmp(aux2,mypassword)!=0)sprintf(auxbuf,"wrong password");
					else {
						for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
						if(*aux1=='\0')sprintf(auxbuf,"missed command");
						else {
							*aux1='\0';
							// reload configuration
							if(strcmp(aux2,"reload")==0){
								myconfig();
								sprintf(auxbuf,"configuration reloaded");
							}
							// reload common black list
							else if(strcmp(aux2,"recbl")==0){
								myloadcommonblacklist();
								sprintf(auxbuf,"common black list reloaded");
							}
							// insert
							else if(strcmp(aux2,"insert")==0){
								for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
								if(*aux1=='\0')sprintf(auxbuf,"missed source IP");
								else {
									*aux1='\0';
									// check ipsrc inside 10.32.0.0/12
									inet_pton(AF_INET,aux2,&(netip.sin_addr));
									ipsrcaddr=ntohl(netip.sin_addr.s_addr);
									if((ipsrcaddr&IPMASK12)!=IPCLASS)sprintf(auxbuf,"wrong source IP");
									else {
										ipidx=ipsrcaddr-IPCLASS;
										for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
										if(*aux1=='\0')sprintf(auxbuf,"missed profile IP");
										else {
											*aux1='\0';
											// check ipprof inside 127.127.0.0/16
											inet_pton(AF_INET,aux2,&(netip.sin_addr));
											ipprofaddr=ntohl(netip.sin_addr.s_addr);
											if((ipprofaddr&IPMASK16)!=IPPROF)sprintf(auxbuf,"wrong profile IP");
											else {
												myprofile[ipidx]=ipprofaddr;
												sprintf(auxbuf,"user profile inserted");
											}
										}
									}
								}
							}
							// delete
							else if(strcmp(aux2,"delete")==0){
								for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
								if(*aux1=='\0')sprintf(auxbuf,"missed source IP");
								else {
									*aux1='\0';
									// check ipsrc inside 10.32.0.0/12
									inet_pton(AF_INET,aux2,&(netip.sin_addr));
									ipsrcaddr=ntohl(netip.sin_addr.s_addr);
									if((ipsrcaddr&IPMASK12)!=IPCLASS)sprintf(auxbuf,"wrong source IP");
									else {
										ipidx=ipsrcaddr-IPCLASS;
										myprofile[ipidx]=0;
										sprintf(auxbuf,"user profile removed");
									}
								}
							}
							// class
							else if(strcmp(aux2,"class")==0){
								for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
								if(*aux1=='\0')sprintf(auxbuf,"missed source IP");
								else {
									*aux1='\0';
									// check ipsrc inside 10.32.0.0/12
									inet_pton(AF_INET,aux2,&(netip.sin_addr));
									ipsrcaddr=ntohl(netip.sin_addr.s_addr);
									if((ipsrcaddr&IPMASK12)!=IPCLASS)sprintf(auxbuf,"wrong source IP");
									else {
										ipidx=ipsrcaddr-IPCLASS;
										if(myprofile[ipidx]==0)sprintf(auxbuf,"user profile IP %s without class",aux2);
										else {
											ipclassaddr=htonl(myprofile[ipidx]);
											inet_ntop(AF_INET,&ipclassaddr,ipbuf,sizeof(ipbuf));
											sprintf(auxbuf,"user profile IP %s into class %s",aux2,ipbuf);
										}
									}
								}
							}
							// stat
							else if(strcmp(aux2,"stats")==0){
								for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
								if(*aux1=='\0')sprintf(auxbuf,"missed IP");
								else {
									*aux1='\0';
									inet_pton(AF_INET,aux2,&(netip.sin_addr));
									ipsrcaddr=ntohl(netip.sin_addr.s_addr);
									mystatus=myipsearch(ipsrcaddr);
									if(mystatus==-1)sprintf(auxbuf,"IP not configured");
									else {
										curtime=time(NULL);
										myuptime=difftime(curtime,starttime);
										ipsrcaddr=htonl(myipclass[mystatus].ipv4);
										inet_ntop(AF_INET,&ipsrcaddr,ipbuf,sizeof(ipbuf));
										sprintf(auxbuf,"IPnet=%s/%d id=%s uptime=%.0lf totquery=%lu filtered=%lu",ipbuf,myipclass[mystatus].cidr,myipclass[mystatus].id,myuptime,myipclass[mystatus].totquery,myipclass[mystatus].totfiltered);
									}
								}
							}
							// status
							else if(strcmp(aux2,"status")==0){
								sprintf(auxbuf,"start=%s totallquery=%'lu totallfiltered=%'lu totmalformed=%'lu totoutscope=%'lu",cstarttime,totallquery,totallfiltered,totmalformed,totoutscope);
							}
							// unknown
							else sprintf(auxbuf,"command unknown");
						}
					}
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
		else  {
			// user whitelist
			wlok=0;
			if((query==1||query==28) && domsearch(myipclass[myclass].mywl,myipclass[myclass].nmywl,dominio))wlok=1;
			// user blacklist
			blok=0;
			if(!wlok && (query==1||query==28) && domsearch(myipclass[myclass].mybl,myipclass[myclass].nmybl,dominio))blok=1;
			// common black list
			cblok=0;
			if(!wlok && !blok && (query==1||query==28) && myipclass[myclass].bl && domsearch(commonblacklist,totcommonblacklist,dominio))cblok=1;
			// set splash
			if(cblok || blok){
				myipclass[myclass].totfiltered++;
				totallfiltered++;
				if(query==28)lenrecv=12+lenanswer+28;
				else lenrecv=12+lenanswer+16;
				if(lenrecv<BUFMSG){
					recv[0]=*myarg->mesg; recv[1]=*(myarg->mesg+1); recv[2]=129; recv[3]=128; recv[4]=*(myarg->mesg+4); recv[5]=*(myarg->mesg+5); recv[6]=0; recv[7]=1; recv[8]=0; recv[9]=0; recv[10]=0; recv[11]=0;
					memcpy(recv+12,myarg->mesg+12,lenanswer);
					aux1=recv+12+lenanswer;
					if(query==28){
						aux1[0]=192; aux1[1]=12; aux1[2]=0; aux1[3]=28; aux1[4]=0; aux1[5]=1; aux1[6]=0; aux1[7]=0; aux1[8]=14; aux1[9]=16; aux1[10]=0; aux1[11]=16;
						inet_pton(AF_INET6,ipv6splash,&(reqaddr6.sin6_addr));
						memcpy(aux1+12,&reqaddr6.sin6_addr.s6_addr,16);
					}
					else {
						aux1[0]=192; aux1[1]=12; aux1[2]=0; aux1[3]=1; aux1[4]=0; aux1[5]=1; aux1[6]=0; aux1[7]=0; aux1[8]=14; aux1[9]=16; aux1[10]=0; aux1[11]=4;
						inet_pton(AF_INET,ipv4splash,&(reqaddr.sin_addr));
						memcpy(aux1+12,&reqaddr.sin_addr.s_addr,4);
					}
				}
			}
			
			// resolution
			else {
				sockreq=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
				tv.tv_sec=0;
				tv.tv_usec=TIMEOUTUSEC;
				setsockopt(sockreq,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
				memset((char *)&reqaddr,0,sizeof(reqaddr));
				reqaddr.sin_family=AF_INET;
				reqaddr.sin_addr.s_addr=inet_addr(dnserver);
				reqaddr.sin_port=htons(53);
				sendto(sockreq,myarg->mesg,myarg->lenmesg,0,(struct sockaddr *)&reqaddr,sizeof(reqaddr));
				lenrecv=recvfrom(sockreq,recv,BUFMSG,0,NULL,NULL);
				close(sockreq);
				if(lenrecv<1){
					sockreq=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
					tv.tv_sec=0;
					tv.tv_usec=TIMEOUTUSEC;
					setsockopt(sockreq,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
					memset((char *)&reqaddr,0,sizeof(reqaddr));
					reqaddr.sin_family=AF_INET;
					reqaddr.sin_addr.s_addr=inet_addr(bkp1dns);
					reqaddr.sin_port=htons(53);
					sendto(sockreq,myarg->mesg,myarg->lenmesg,0,(struct sockaddr *)&reqaddr,sizeof(reqaddr));
					lenrecv=recvfrom(sockreq,recv,BUFMSG,0,NULL,NULL);
					close(sockreq);
				}
				if(lenrecv<1){
					sockreq=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
					tv.tv_sec=0;
					tv.tv_usec=TIMEOUTUSEC;
					setsockopt(sockreq,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
					memset((char *)&reqaddr,0,sizeof(reqaddr));
					reqaddr.sin_family=AF_INET;
					reqaddr.sin_addr.s_addr=inet_addr(bkp2dns);
					reqaddr.sin_port=htons(53);
					sendto(sockreq,myarg->mesg,myarg->lenmesg,0,(struct sockaddr *)&reqaddr,sizeof(reqaddr));
					lenrecv=recvfrom(sockreq,recv,BUFMSG,0,NULL,NULL);
					close(sockreq);
				}
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
	tid=(pthread_t *)malloc(NTHREAD*sizeof(pthread_t));
	
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
	
	for(j=0;;){
		// receive request and launch a processing thread
		myargs[j].lenmesg=recvfrom(sockfd,myargs[j].mesg,BUFMSG,0,(struct sockaddr *)&myargs[j].cliaddr,&len);
		pthread_create(&(tid[j]),NULL,&manage,&myargs[j]);
		pthread_detach(tid[j]);
		if(++j==NTHREAD)j=0;
	}
	
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
