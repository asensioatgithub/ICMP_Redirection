#include<stdio.h>
#include<pcap.h>
#include<unistd.h>    // int getopt_long(int argc,char * const argv[ ],const char * optstring,const struct option *longopts,int *longindex );
#include<time.h>      //  struct tm *localtime(const time_t *timer) 
#include"sniffer.h"
#include<arpa/inet.h> // char *inet_ntoa (struct in_addr);  u_short ntohs(u_short );
#include<math.h>	//pow()
#include<string.h>
/*
struct tm {
   int tm_sec;         
   int tm_min;        
   int tm_hour;        
   int tm_mday;        
   int tm_mon;         
   int tm_year;       
   int tm_wday;        
   int tm_yday;        
   int tm_isdst;         
};
*/
#define MAXSIZE 1500
#define PROMISC 0
#define TO_MS 3

u_short con_iphdlen(const u_char *p){
	u_short num = 0;
	u_short temp = *p;
	for(int i=0;i<4;i++){
		if((temp&1)==1)
			num+=pow(2,i);
		temp=temp>>1;
	}
	return num;
};


struct sniff_ethernet * arp = NULL;
struct sniff_ip *ip = NULL;
struct sniff_tcp * tcp= NULL;
struct sniff_icmp * icmp= NULL;
struct sniff_udp * udp= NULL;

const char *option = "i:t:p:ms:d:x";
const char *ip_type[3]={"ICMP","TCP","UDP"};


static int mac_flag = 0;
static int icmp_flag = 0;
static int x_flag = 0; //print data or not 
static int ip_type_num = -1;
static int prt = 0;
static int ether_type = 0; //1:ip 2:arp 3:rarp

/*
int main(int argc,char *argv[]){

	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevsp = NULL;
	pcap_if_t *curdev = NULL;
	pcap_t *handle = NULL;
	struct bpf_program fp;
	
	char ip_exp[15] = "ip and ";
	//char *icmp_exp = "icmp[icmptype] == icmp-echoreply or icmp[icmptype] == icmp-echo";
	char port_exp[12] = " and port ";
	char dstip_exp[18] = " and dst host ";
	char srcip_exp[18] = " and src host ";
	char filter_exp[100] = "";
	bpf_u_int32 ip;  
	bpf_u_int32 mask; 
	const u_char *packet;
	struct pcap_pkthdr header;
	/*
	struct pcap_pkthdr {
		struct timeval ts;	// time stamp 
		bpf_u_int32 caplen;	// length of portion present //
		bpf_u_int32 len;	// length this packet (off wire) //
     };
    
	struct timeval {
          time_t       tv_sec;     // seconds time_t 这种类型就是用来存储从1970年到现在经过了多少秒
          suseconds_t   tv_usec; // microseconds 
     };
     */
     /*
     char ch;
	while((ch=getopt(argc,argv,option)) != -1){
		switch(ch){
			case'i':
				printf("listening on %s", optarg);
				dev = optarg;
				break;
			case't':
				strcat(ip_exp,optarg);
				printf(", protocol-type %s ", optarg);
				strcat(filter_exp,ip_exp);
				break;
			case'p':
				printf(", port %s", optarg);
				strcat(port_exp,optarg);
				strcat(filter_exp,port_exp);
				break;
			case'm':
				mac_flag = 1;
				break;
			case's':
				printf(", from %s", optarg);
				strcat(srcip_exp,optarg);
				strcat(filter_exp,srcip_exp);			
				break;
			case'd':
				printf(", to %s", optarg);
				strcat(dstip_exp,optarg);
				strcat(filter_exp,dstip_exp);					
				break;
			case'x':
				x_flag = 1;
				break;
			default:
				printf("opther option:%c\n", ch);
		}
	}
     printf("\n");
     handle = pcap_open_live(dev, MAXSIZE, PROMISC, TO_MS, errbuf);
	if(handle == NULL){
		printf("Couldn't open device%s: %s\n", dev, errbuf);
		return(2);
	}
	
	if(pcap_lookupnet(dev, &ip, &mask, errbuf) == -1){
		printf("couldn't get ip or mask: %s\n", errbuf);
		return(2); 
	}
	printf("\n%s\n",filter_exp);
	
	if(pcap_compile(handle, &fp, filter_exp, 0, mask) == -1){
		printf("Couldn't parse filte %s : %s\n", filter_exp, errbuf);
		return(2);
	}
	pcap_setfilter(handle, &fp); 
	pcap_loop(handle, -1, callback,NULL);  //int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)	
	pcap_freecode(&fp);
	pcap_close(handle);
	return(0);
}
*/

/*
void callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
	printf("\n");
	printtime(header);
	sniffer_ethernet(packet, &arp);
	prt = sniffer_ip(packet, &ip);
	print_addr(ip,arp);
	switch(ether_type){
		case 1:
			print_ip(ip);
			break;
		case 2:
		//	print_arp();
			break;
		case 3:
		//	print_rarp();
			break;
		default:	
			printf("noting found of frame_type\n");
			break;
	}
	
//	printf("%d", ip_type_num);
	
	if(prt == 1){			//ICMP protocol
		sniffer_icmp(packet, &icmp);
		ip_type_num = 0;
		print_icmp(ip, arp, icmp);
	}
	else if(prt == 6){		//TCP protocol
		sniffer_tcp(packet, &tcp);
		ip_type_num = 1;
		print_tcp(ip, arp, tcp); 
	}
	else if(prt == 17){		//UDP protocol
		sniffer_udp(packet,&udp);
		ip_type_num = 2;
	}
	else{
		
	}
	
	if(x_flag == 1){
		u_short total_size = ntohs(ip->ip_len)+14;
		print_X_data(packet,total_size);
	}

}
*/

void printtime(const struct pcap_pkthdr *header){
	struct tm *time = localtime(&header->ts.tv_sec);
	printf("%02d:%02d:%02d ", time->tm_hour, time->tm_min, time->tm_sec);	
}



void sniffer_ethernet(const u_char *packet, struct sniff_ethernet **arp){
	*arp = (struct sniff_ethernet *)packet;	
	//frame type
	u_short type = ntohs((*arp)->ether_type);
	if(type == 2048){   //arp->ether_type: 0800(ip),0806(arp),8035(rarp). Big-endian
		printf("IP ");
		ether_type = 1;
	}
	else if (type == 2054){
		printf("ARP ");
		ether_type = 2;
	}
	else if(type == 32821){
		printf("RARP ");
		ether_type = 3;
	}
}

int sniffer_ip(const u_char *packet, struct sniff_ip **ip){
	int protocol = -1;
	u_char *p = (u_char*)packet;
	p=p+14;
	*ip = (struct sniff_ip *) p;
	protocol = (int)(*ip)->ip_p;
	return protocol;
}

void sniffer_tcp(const u_char *packet, struct sniff_tcp **tcp){
	u_char *p = (u_char*)packet;
	p+=34;
	*tcp =  (struct sniff_tcp *) p;
}

void sniffer_icmp(const u_char *packet, struct sniff_icmp **icmp){
	u_char *p = (u_char*)packet;
	p+=34;
	*icmp = (struct sniff_icmp*)p; 
}

void sniffer_udp(const u_char *packet, struct sniff_udp **udp){

}

void print_icmp(struct sniff_ip *ip, struct sniff_ethernet *arp, struct sniff_icmp *icmp){
	
	int icmp_type = icmp->icmp_type;
	if(icmp_type == 0)
		printf("ICMP echo reply");
	else if(icmp_type == 3)
		printf("ICMP Destination Unreachable");
	else if(icmp_type == 5)
		printf("ICMP Redirect");
	else if(icmp_type == 8)
		printf("ICMP echo request");
	else 
		printf("Unknown ICMP type");
	printf(", id %d, seq %d, length %d", ntohs(icmp->icmp_Id), ntohs(icmp-> icmp_sequence), ntohs(ip->ip_len)-20); //icmp-total-length = ip_total_length - ip_header_length
}

//little-endian and big-endian
u_short reversebytes(const u_short *src_bytes){
	u_short num=0;
	u_char *p =(u_char*) src_bytes;
	p+=1;
	int temp = *p;
	for(int i=0;i<8;i++){
		if((temp&1)==1)
			num+=pow(2,i);
		temp=temp>>1;
	}
	p-=1;
	temp = *p;
	for(int i=0;i<5;i++){
		if((temp&1)==1)
			num+=pow(2,i+8);
		temp>>=1;
	}
	return num;
}

void print_addr(struct sniff_ip *ip, struct sniff_ethernet *arp){
	if(mac_flag == 0){
		//print source host ip address
		printf("%s -> ", inet_ntoa(ip->ip_src));
		//print destination host ip address
		printf("%s\n", inet_ntoa(ip->ip_dst));
	}
	else{
		u_char *shost = arp->ether_shost;
		printf("%s[%02x:%02x:%02x:%02x:%02x:%02x] -> ",inet_ntoa(ip->ip_src), *shost, *(shost+1), *(shost+2), *(shost+3), *(shost+4) ,*(shost+5));	
		//print destination host mac address
		u_char *dhost = arp->ether_dhost;
		printf("%s[%02x:%02x:%02x:%02x:%02x:%02x]\n",inet_ntoa(ip->ip_dst), *dhost, *(dhost+1), *(dhost+2), *(dhost+3), *(dhost+4) ,*(dhost+5));
	}
}

void print_X_data(const u_char *packet, u_short total_size){
	printf("\n");
	//printf("%d ",total_size);
	u_short line_count = total_size/16; 
	u_char * cur_hex = (u_char *)packet;
	u_char * cur_char = cur_hex;
	u_short c = 1;
	printf("\t ");
	
	while(c <= total_size){
		
		if(c<=14)           //arp_header
			printf("\033[1;32m%02x\33[0m", *cur_hex);
		else if(c<=34)            //ip_header
			printf("\033[1;34m%02x\33[0m", *cur_hex);
		else if((ip_type_num==1||ip_type_num==17) && c<=42)	//icmp_header || udp_header
			printf("\033[1;35m%02x\33[0m", *cur_hex);
		else if(c<=54)			//tcp_header
			printf("\033[1;35m%02x\33[0m", *cur_hex);
		else if(c>=67&&c<=total_size)
			printf("\033[1;31m%02x\33[0m", *cur_hex);
		else
			printf("%02x", *cur_hex);
		if(c%2 ==0) printf(" ");
		if(c%16 == 0) {
			printf("   ");
			for(int i=0;i<16;i++){
				if (isprint(*cur_char))
					printf("%c", *cur_char);
				else
					printf(".");
				cur_char++;
			}
			printf("\n\t ");
			
		}
		if(c==total_size){
			printf("   ");
			int l = 39 - 2*(total_size%16)-(total_size%16)/2+1;
			for(int i=0;i<l;i++)
				printf("%c",' ');
			for(int i=0;i<total_size%16;i++){
				if (isprint(*cur_char))
					printf("%c", *cur_char);
				else
					printf(".");
				cur_char++;
			}
			printf("\n ");
		}
		c++;cur_hex+=1; 
	}
	
	printf("\n");
	
}


void print_ip(const struct sniff_ip *ip){
	printf("\t Version:ipv%d, TOS:0x%02x, Ip Header Length:%d, Total Length:%d, id:%d, offset:%d, ttl:%d, protol:%s\n\t ", (ip->ip_vhl)>>4, ip->ip_tos, con_iphdlen(&(ip->ip_vhl))*4, ntohs(ip->ip_len), ntohs(ip->ip_id),reversebytes(&(ip->ip_off)), ip->ip_ttl, ip_type[ip_type_num]);
}

void print_tcp(struct sniff_ip *ip, struct sniff_ethernet *arp, struct sniff_tcp *tcp){
	
	
	printf("sport:%d, dport:%d, seq:%u, ack:%u, win:%d, ", ntohs(tcp->th_sport), ntohs(tcp->th_dport), ntohl(tcp->th_seq), ntohl(tcp->th_ack), ntohs(tcp->th_win));
	tcp_flags(&(tcp->th_flags));
	
}

unsigned int reverseint(const tcp_seq *src_bytes){
	unsigned int num=0;
	u_char *p =(u_char*) src_bytes;
	u_char *cur = p; 
	u_short temp = 0;
     for(int j=3;j>=0;j--){
     	cur = p+j;
     	temp = *cur;
     	for(int i=0;i<8;i++){
			if((temp&1)==1)
				num+=pow(2,i+8*j);
			temp>>=1;
		}
     }
     
	return num;
}

void tcp_flags(u_char * flag){
	u_short temp = *flag;
	printf("Flags:|");
	for(int i=0;i<8;i++){
		if((temp&1)==1){
			printf("%s|", th_flags[i]);
		}
		temp=temp>>1;	
	}
}
