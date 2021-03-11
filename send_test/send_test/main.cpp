//control command
#include <stdio.h>
#include <stdlib.h>
#include<iostream>
#include <pcap.h>
//#include <opencv2/core/core.hpp>
//#include <opencv2/highgui/highgui.hpp>
//#include <opencv2/imgproc/imgproc.hpp>
//#include <opencv2/video/tracking.hpp>
#include <string.h>
#include <vector>
#include <net/if.h>				//struct ifreq
#include <sys/ioctl.h>			//ioctl¡¢SIOCGIFADDR
#include <sys/socket.h>
#include <netinet/ether.h>		//ETH_P_ALL
#include <netpacket/packet.h>	//struct sockaddr_ll
#include <unistd.h>
using namespace std;
//using namespace cv;


#include<netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 2

struct ip_header  //定义IP数据报头
{
    unsigned   char     ihl : 4;              //ip   header   length
    unsigned   char     version : 4;          //version
    u_char              tos;                //type   of   service
    u_short             tot_len;            //total   length
    u_short             id;                 //identification
    u_short             frag_off;           //fragment   offset
    u_char              ttl;                //time   to   live
    u_char              protocol;           //protocol   type
    u_short             check;              //check   sum
    u_int               saddr;              //source   address
    u_int               daddr;              //destination   address
};


struct tcphdr //定义TCP数据报头
{
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
    u_int16_t res1 : 4;
    u_int16_t doff : 4;
    u_int16_t fin : 1;
    u_int16_t syn : 1;
    u_int16_t rst : 1;
    u_int16_t psh : 1;
    u_int16_t ack : 1;
    u_int16_t urg : 1;
    u_int16_t res2 : 2;
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};



struct udphdr
{
    u_int16_t source;         /* source port */
    u_int16_t dest;           /* destination port */
    u_int16_t len;            /* udp length */
    u_int16_t checkl;
    //u_int16_t check2;/* udp checksum */
};

char* uint_to_addr(u_int addr);

u_int16_t in_cksumh(u_int16_t * addr, int len)
{
    int     nleft = len;
    u_int32_t sum = 0;
    u_int16_t *w = addr;
    u_int16_t answer = 0;

    /*
    * Our algorithm is simple, using a 32 bit accumulator (sum), we add
    * sequential 16 bit words to it, and at the end, fold back all the
    * carry bits from the top 16 bits into the lower 16 bits.
    */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);     /* add carry */
    answer = ~sum;     /* truncate to 16 bits */
    return (answer);
}

#define SAMPLE_PRT(fmt...)   \
    do {\
        printf("[%s]-%d: ", __FUNCTION__, __LINE__);\
        printf(fmt);\
    }while(0)


// if interfaces 接口
 int main(int argc, char *argv[])
 {
     /* Create a new socket of type TYPE in domain DOMAIN, using
        protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
        Returns a file descriptor for the new socket, or -1 for errors.  */
     /*
        family：协议族 这里写 PF_PACKET
        type：  套接字类，这里写 SOCK_RAW
        protocol：协议类别，指定可以接收或发送的数据包类型，不能写 “0”，取值如下，注意，传参时需要用 htons() 进行字节序转换。
            ETH_P_IP：IPV4数据包
            ETH_P_ARP：ARP数据包
            ETH_P_ALL：任何协议类型的数据包
    原文链接：https://blog.csdn.net/tennysonsky/article/details/44676377
    */
    int sock_raw_fdh = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); /* Protocol families.  */ //网络层
    u_char sendbufferh[44] = { 0 };
    u_char finishsign[4] = {"EOF"};
    printf("%s\n",finishsign);
    struct sockaddr_ll sllh;
    /* Interface request structure used for socket ioctl's.  All interface
       ioctl's must have parameter definitions which begin with ifr_name.
       The remainder may be interface specific.  */
    struct ifreq ethreqh;
    int lenh;

    ether_header* pether_header = (ether_header*)sendbufferh;//以太网首部指针
    ip_header* pip_herder = (ip_header*)(sendbufferh + sizeof(ether_header));//IP数据头指针
    udphdr* pudp_herder = (udphdr*)(sendbufferh + sizeof(ether_header)+sizeof(ip_header));//UDP数据头指针

///-----------------------------------------------------------------------------------------------------------------------
    pcap_if_t *alldevs,*d; //结构体链表,链表结构体大小
    uint devCount=0;
    char errBuf[PCAP_ERRBUF_SIZE];
    /* Retrieve the device list */
    //官方推荐使用此方法,use 'pcap_findalldevs' and use the first device
    if(pcap_findalldevs(&alldevs, errBuf) == -1) //与netstat -i效果一样
    {
        SAMPLE_PRT("can't open file %s\n", errBuf);
        return -1;
    }

    if(alldevs->name==NULL)
    {
        printf("device is NULL\n");
        exit(-1);
    }
    else
    {
        printf("acessed device : %s\n",alldevs->name);
    }

    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s ", ++devCount, d->name);//网络设备名
        if (d->description)
            printf(" %s\n", d->description);
        else
            printf(" No description available\n");
    }


    bpf_u_int32 netp = 0, maskp = 0;
//    pcap_t * pcap_handle = NULL;
    int ret = 0;

    //获得网络号和掩码,
    ret = pcap_lookupnet(alldevs->name, &netp, &maskp, errBuf);
    if(ret == -1)
    {
        printf(errBuf);
        exit(-1);
    }

    /*
    netp 1a8c0
    netp 192.168.1.0
    maskp 255.255.255.0
    */
    printf("netp %x\n",netp);
    printf("netp %d.%d.%d.%d\n",*((uint8_t*)&netp+0),*((uint8_t*)&netp+1),*((uint8_t*)&netp+2),*((uint8_t*)&netp+3));
    printf("maskp %d.%d.%d.%d\n",*((uint8_t*)&maskp+0),*((uint8_t*)&maskp+1),*((uint8_t*)&maskp+2),*((uint8_t*)&maskp+3));


///-----------------------------------------------------------------------------------------------------------------------

    //针对以太网头部源地址进行赋值
    pether_header->ether_shost[0] = 0x00;       //0x0 * 16 + 0x0;;
    pether_header->ether_shost[1] = 0x04;       //0x2 * 16 + 0x1;
    pether_header->ether_shost[2] = 0x4b;       //0x2 * 16 + 0x7;
    pether_header->ether_shost[3] = 0xa5;       //0x2 * 16 + 0x3;
    pether_header->ether_shost[4] = 0x42;       //0x7 * 16 + 0x2;
    pether_header->ether_shost[5] = 0xb7;       //0xf * 16 + 0xe;

    //针对以太网头部目的地址进行赋值
    pether_header->ether_dhost[0] = 0x00;       //0x0 * 16 + 0x0;;
    pether_header->ether_dhost[1] = 0x04;       //0x1 * 16 + 0xF;
    pether_header->ether_dhost[2] = 0x4d;       //0xD * 16 + 0x0;
    pether_header->ether_dhost[3] = 0xa5;       //0x1 * 16 + 0x6;
    pether_header->ether_dhost[4] = 0x1a;       //0x6 * 16 + 0x3;
    pether_header->ether_dhost[5] = 0xde;       //0x7 * 16 + 0x1;

    //针对以太网协议进行赋值
    pether_header->ether_type = htons(ETHERTYPE_IP);
    if ((sizeof(ip_header) % 4) != 0)
    {
        printf("[IP Header error]/n");
        //   return;
    }


///-----------------------------------------------------------------------------------------------------------------------
    char* ifr_name_=NULL;
//    ifr_name_ = (char*)malloc(IFNAMSIZ);
//    free(ifr_name_); //free malloc必须配对使用否则内存泄漏
    /*char *strncpy(char *dest, const char *src, int n)
     表示把src所指向的字符串中以src地址开始的前n个字节复制到dest所指的数组中，并返回被复制后的dest
    */
    ifr_name_ =strncpy(ethreqh.ifr_name, alldevs->name, IFNAMSIZ);
    printf("ifr_name_  used device : %s\n",ifr_name_);
//    free(ifr_name_); // 报错double free or corruption (out): 0xbe936af8 ***，应该是对栈进行释放

    if(-1 == ioctl(sock_raw_fdh, SIOCGIFINDEX, &ethreqh))  //ioctl Usually -1 indicates error
    {
        perror("ioctl");
        exit(-1);
    }
//    printf("net device : %s\n",ethreqh.ifr_ifrn.ifrn_name);
//    printf(" mask : %s ,",inet_ntoa(((struct sockaddr_in*)&(ethreqh.ifr_addr))->sin_addr)); //
//    printf(" port num : %d \n",((struct sockaddr_in*)&(ethreqh.ifr_addr))->sin_port); //

    if(ioctl(sock_raw_fdh,SIOCGIFNETMASK,&ethreqh)==-1)//获取子网掩码
    {
        perror("ioctl");
        exit(-1);
    }
    //sockaddr_in <==> sockaddr
    printf("net device : %s\n",ethreqh.ifr_ifrn.ifrn_name);
    printf(" mask : %s ,",inet_ntoa(((struct sockaddr_in*)&(ethreqh.ifr_addr))->sin_addr)); //子网掩码
    printf(" port num : %d \n",((struct sockaddr_in*)&(ethreqh.ifr_addr))->sin_port); //网络字节顺序的端口号!

    //struct ifreq学习和实例  https://www.cnblogs.com/zhengAloha/p/8371177.html
    //sockaddr和sockaddr_in详解 https://blog.csdn.net/will130/article/details/53326740
    if (ioctl(sock_raw_fdh, SIOCGIFADDR, &ethreqh) <  0)//get PA address 获取接口地址 192.168.1.120
    {
        perror("ioctl");
        exit(-1);
    }
    printf("if addr %x\n",((struct sockaddr_in*)&(ethreqh.ifr_addr))->sin_addr);
    printf("if addr %s\n", inet_ntoa(((struct sockaddr_in*)&(ethreqh.ifr_addr))->sin_addr));

    printf("net device : %s ,",ethreqh.ifr_ifrn.ifrn_name); //网络设备名 网卡名
    printf(" ip addr : %s ,",inet_ntoa(((struct sockaddr_in*)&(ethreqh.ifr_addr))->sin_addr)); //网卡ip地址
    printf(" port num : %d \n",((struct sockaddr_in*)&(ethreqh.ifr_addr))->sin_port); //网络字节顺序的端口号!



///-----------------------------------------------------------------------------------------------------------------------
    //构建IP数据头
    pip_herder->ihl = sizeof(ip_header) / 4; //以4字节为单位
    pip_herder->version = 4;//设定版本号
    pip_herder->tos = 0; //设定类型
    pip_herder->tot_len = htons(sizeof(sendbufferh)-sizeof(ether_header));//设定长度
    pip_herder->id = htons(0x1000);//设定ID
    pip_herder->frag_off = htons(0);//设定偏移量
    pip_herder->ttl = 0x80;//设定TTL
    pip_herder->protocol = IPPROTO_UDP;//设定协议类型
    pip_herder->check = 0; //设定检验和
    //自动获取网络设备的接口地址，
    pip_herder->saddr = *(uint32_t*)&((struct sockaddr_in*)&(ethreqh.ifr_addr))->sin_addr;//inet_addr("192.168.1.155"); //设定源地址
    pip_herder->daddr = inet_addr("192.168.1.120");//设定目的地址
    pip_herder->check = in_cksumh((u_int16_t*)pip_herder, sizeof(ip_header)); //重新设定检验和

    printf("pip_herder->saddr %x\n",pip_herder->saddr); //0x7801a8c0对应顺序 120 1 168 192
    printf("pip_herder->saddr %d.%d.%d.%d\n",*((uint8_t*)&pip_herder->saddr+0),*((uint8_t*)&pip_herder->saddr+1),*((uint8_t*)&pip_herder->saddr+2),*((uint8_t*)&pip_herder->saddr+3)); //net ip 192.168.1.120
//    printf("maskp %d.%d.%d.%d\n",*((uint8_t*)&maskp+0),*((uint8_t*)&maskp+1),*((uint8_t*)&maskp+2),*((uint8_t*)&maskp+3)); //mask

    //构建UDP数据头;
    pudp_herder->dest = htons(1024); //目的端口号
    pudp_herder->source = htons(1024);//源端口号
    pudp_herder->len = htons(sizeof(sendbufferh)-sizeof(ether_header)-sizeof(ip_header));//设定长度 44-14-20
//    cout<<pudp_herder->len<<endl; //2560 0xa0
//    cout <<"len "<<sizeof(sendbufferh)-sizeof(ether_header)-sizeof(ip_header)<<endl; //10 0x0a
    pudp_herder->checkl = 0;//设定检验和


    //htons 变量从主机字节顺序转变成网络字节顺序 小段序-->大端序
    printf("ether_header %d ip_header %d udphdr %d\n",sizeof(ether_header),sizeof(ip_header),sizeof(udphdr));  //(6+6+2)14+20+8

///-----------------------------------------------------------------------------------------------------------------------
    


    /* Set N bytes of S to 0.  */
    bzero(&sllh, sizeof(sllh));
    //接口索引号sll_ifindex为0时表示使用有效的所有接口,接口的sll_ifindex值可以通过ioctl获得,取得的值保存在ifr结构体的ifr_ifindex中，ifr结构类型为struct ifreq
    sllh.sll_ifindex = ethreqh.ifr_ifindex; /* interface index      */ //接口的索引号

//    int read_len = 2;
    u_int8_t buffer1[3] = {99,19,100};
    memcpy(sendbufferh+41,buffer1,sizeof(buffer1)/sizeof(u_int8_t));
    int numm=0;

    printf("sll_ifindex %d\n",sllh.sll_ifindex);

    while(1){
        /* Send N bytes of BUF on socket FD to peer at address ADDR (which is
           ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.

           This function is a cancellation point and therefore not marked with
           __THROW.  */
        lenh = sendto(sock_raw_fdh, sendbufferh, 44, 0 , (struct sockaddr *)&sllh, sizeof(sllh));
        if(lenh == -1)
        {
            perror("sendto");
        }
        cout<<numm++<</*" lalalallalalallaa"<<*/endl;
        printf("     %d  %d  %d\n",sendbufferh[41],sendbufferh[42],sendbufferh[43]);
        usleep(40000);
    }
    usleep(40000);

}


 /**
  * \file getifstat.c
  * \author  wzj
  * \brief 访问这个struct ifconf 修改，查询状态
  * \version
  * \note
  * \date: 2012年08月11日星期六22:55:25
  */
 #include <net/if.h>       /* for ifconf */
 #include <linux/sockios.h>    /* for net status mask */
 #include <netinet/in.h>       /* for sockaddr_in */
 #include <sys/socket.h>
 #include <sys/types.h>
 #include <sys/ioctl.h>
 #include <stdio.h>

 #define MAX_INTERFACE   (16)

 void port_status(unsigned int flags);

 /* set == 0: do clean , set == 1: do set! */
 int set_if_flags(char *pif_name, int sock, int status, int set)
 {
     struct ifreq ifr;
     int ret = 0;

     strncpy(ifr.ifr_name, pif_name, strlen(pif_name) + 1);
     ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
     if(ret)
         return -1;
     /* set or clean */
     if(set)
         ifr.ifr_flags |= status;
     else
         ifr.ifr_flags &= ~status;
     /* set flags */
     ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
     if(ret)
         return -1;

     return 0;
 }

 int get_if_info(int fd)
 {
     struct ifreq buf[MAX_INTERFACE];
     struct ifconf ifc;
     int ret = 0;
     int if_num = 0;

     ifc.ifc_len = sizeof(buf);
     ifc.ifc_buf = (caddr_t) buf;

     ret = ioctl(fd, SIOCGIFCONF, (char*)&ifc);
     if(ret)
     {
         printf("get if config info failed");
         return -1;
     }
     /* 网口总数 ifc.ifc_len 应该是一个出入参数 */
     if_num = ifc.ifc_len/sizeof(struct ifreq);
     printf("interface num is interface = %d\n", if_num);
     while(if_num-- > 0)
     {
         printf("net device: %s\n", buf[if_num].ifr_name);
         /* 获取第n个网口信息 */
         ret = ioctl(fd, SIOCGIFFLAGS, (char*)&buf[if_num]);
         if(ret)
             continue;

         /* 获取网口状态 */
         port_status(buf[if_num].ifr_flags);

         /* 获取当前网卡的ip地址 */
         ret = ioctl(fd, SIOCGIFADDR, (char*)&buf[if_num]);
         if(ret)
             continue;
         printf("IP address is: \n%s\n", inet_ntoa(((struct sockaddr_in *)(&buf[if_num].ifr_addr))->sin_addr));

         /* 获取当前网卡的mac */
         ret = ioctl(fd, SIOCGIFHWADDR, (char*)&buf[if_num]);
         if(ret)
             continue;

         printf("%02x:%02x:%02x:%02x:%02x:%02x\n\n",
             (unsigned char)buf[if_num].ifr_hwaddr.sa_data[0],
             (unsigned char)buf[if_num].ifr_hwaddr.sa_data[1],
             (unsigned char)buf[if_num].ifr_hwaddr.sa_data[2],
             (unsigned char)buf[if_num].ifr_hwaddr.sa_data[3],
             (unsigned char)buf[if_num].ifr_hwaddr.sa_data[4],
             (unsigned char)buf[if_num].ifr_hwaddr.sa_data[5]
             );
     }
 }

 void port_status(unsigned int flags)
 {
     if(flags & IFF_UP)
     {
         printf("is up\n");
     }
     if(flags & IFF_BROADCAST)
     {
         printf("is broadcast\n");
     }
     if(flags & IFF_LOOPBACK)
     {
         printf("is loop back\n");
     }
     if(flags & IFF_POINTOPOINT)
     {
         printf("is point to point\n");
     }
     if(flags & IFF_RUNNING)
     {
         printf("is running\n");
     }
     if(flags & IFF_PROMISC)
     {
         printf("is promisc\n");
     }
 }

 int main_()
 {
     int fd;

     fd = socket(AF_INET, SOCK_DGRAM, 0);
     if(fd > 0)
     {
         get_if_info(fd);
         close(fd);
     }

     return 0;
 }


////send damage assess information
//#include <stdio.h>
//#include <stdlib.h>
//#include<iostream>
//#include <pcap.h>
//#include <opencv2/core/core.hpp>
//#include <opencv2/highgui/highgui.hpp>
//#include <opencv2/imgproc/imgproc.hpp>
//#include <opencv2/video/tracking.hpp>
//#include <string.h>
//#include <vector>
//#include <net/if.h>				//struct ifreq
//#include <sys/ioctl.h>			//ioctl¡¢SIOCGIFADDR
//#include <sys/socket.h>
//#include <netinet/ether.h>		//ETH_P_ALL
//#include <netpacket/packet.h>	//struct sockaddr_ll
//#include <unistd.h>
//using namespace std;
//using namespace cv;

//#define BUFFER_SIZE 2

//struct _wRECT
//{
//    unsigned short left;
//    unsigned short right;
//    unsigned short top;
//    unsigned short bottom;
//};

//struct ip_header  //定义IP数据报头
//{
//    unsigned   char     ihl : 4;              //ip   header   length
//    unsigned   char     version : 4;          //version
//    u_char              tos;                //type   of   service
//    u_short             tot_len;            //total   length
//    u_short             id;                 //identification
//    u_short             frag_off;           //fragment   offset
//    u_char              ttl;                //time   to   live
//    u_char              protocol;           //protocol   type
//    u_short             check;              //check   sum
//    u_int               saddr;              //source   address
//    u_int               daddr;              //destination   address
//};


//struct tcphdr //定义TCP数据报头
//{
//    u_int16_t source;
//    u_int16_t dest;
//    u_int32_t seq;
//    u_int32_t ack_seq;
//    u_int16_t res1 : 4;
//    u_int16_t doff : 4;
//    u_int16_t fin : 1;
//    u_int16_t syn : 1;
//    u_int16_t rst : 1;
//    u_int16_t psh : 1;
//    u_int16_t ack : 1;
//    u_int16_t urg : 1;
//    u_int16_t res2 : 2;
//    u_int16_t window;
//    u_int16_t check;
//    u_int16_t urg_ptr;
//};



//struct udphdr
//{
//    u_int16_t source;         /* source port */
//    u_int16_t dest;           /* destination port */
//    u_int16_t len;            /* udp length */
//    u_int16_t checkl;
//    //u_int16_t check2;/* udp checksum */
//};

//char* uint_to_addr(u_int addr);

//u_int16_t in_cksumh(u_int16_t * addr, int len)
//{
//    int     nleft = len;
//    u_int32_t sum = 0;
//    u_int16_t *w = addr;
//    u_int16_t answer = 0;

//    /*
//    * Our algorithm is simple, using a 32 bit accumulator (sum), we add
//    * sequential 16 bit words to it, and at the end, fold back all the
//    * carry bits from the top 16 bits into the lower 16 bits.
//    */
//    while (nleft > 1) {
//        sum += *w++;
//        nleft -= 2;
//    }
//    /* mop up an odd byte, if necessary */
//    if (nleft == 1) {
//        *(unsigned char *)(&answer) = *(unsigned char *)w;
//        sum += answer;
//    }

//    /* add back carry outs from top 16 bits to low 16 bits */
//    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
//    sum += (sum >> 16);     /* add carry */
//    answer = ~sum;     /* truncate to 16 bits */
//    return (answer);
//}

//int main(int argc, char *argv[]){
//    int sock_raw_fdh = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
//    u_char sendbufferh[107] = { 0 };
//    u_char finishsign[4] = {"EOF"};
//    printf("%s\n",finishsign);
//    struct sockaddr_ll sllh;
//    struct ifreq ethreqh;
//    int lenh;

//    ether_header* pether_header = (ether_header*)sendbufferh;//以太网首部指针
//    ip_header* pip_herder = (ip_header*)(sendbufferh + sizeof(ether_header));//IP数据头指针
//    udphdr* pudp_herder = (udphdr*)(sendbufferh + sizeof(ether_header)+sizeof(ip_header));//UDP数据头指针

//    //针对以太网头部源地址进行赋值
//    pether_header->ether_shost[0] = 0x00;       //0x0 * 16 + 0x0;;
//    pether_header->ether_shost[1] = 0x04;       //0x2 * 16 + 0x1;
//    pether_header->ether_shost[2] = 0x4b;       //0x2 * 16 + 0x7;
//    pether_header->ether_shost[3] = 0xa5;       //0x2 * 16 + 0x3;
//    pether_header->ether_shost[4] = 0x42;       //0x7 * 16 + 0x2;
//    pether_header->ether_shost[5] = 0xb7;       //0xf * 16 + 0xe;

//    //针对以太网头部目的地址进行赋值
//    pether_header->ether_dhost[0] = 0x00;       //0x0 * 16 + 0x0;;
//    pether_header->ether_dhost[1] = 0x04;       //0x1 * 16 + 0xF;
//    pether_header->ether_dhost[2] = 0x4d;       //0xD * 16 + 0x0;
//    pether_header->ether_dhost[3] = 0xa5;       //0x1 * 16 + 0x6;
//    pether_header->ether_dhost[4] = 0x1a;       //0x6 * 16 + 0x3;
//    pether_header->ether_dhost[5] = 0xde;       //0x7 * 16 + 0x1;

//    //针对以太网协议进行赋值
//    pether_header->ether_type = htons(ETHERTYPE_IP);
//    if ((sizeof(ip_header) % 4) != 0)
//    {
//        printf("[IP Header error]/n");
//        //   return;
//    }

//    //构建IP数据头
//    pip_herder->ihl = sizeof(ip_header) / 4; //以4字节为单位
//    pip_herder->version = 4;//设定版本号
//    pip_herder->tos = 0; //设定类型
//    pip_herder->tot_len = htons(sizeof(sendbufferh)-sizeof(ether_header));//设定长度
//    pip_herder->id = htons(0x1000);//设定ID
//    pip_herder->frag_off = htons(0);//设定偏移量
//    pip_herder->ttl = 0x80;//设定TTL
//    pip_herder->protocol = IPPROTO_UDP;//设定协议类型
//    pip_herder->check = 0; //设定检验和
//    pip_herder->saddr = inet_addr("127.0.0.1"); //设定源地址
//    pip_herder->daddr = inet_addr("127.0.0.1");;//设定目的地址
//    pip_herder->check = in_cksumh((u_int16_t*)pip_herder, sizeof(ip_header)); //重新设定检验和

//    //构建UDP数据头;
//    pudp_herder->dest = htons(1024); //目的端口号
//    pudp_herder->source = htons(1024);//源端口号
//    pudp_herder->len = htons(sizeof(sendbufferh)-sizeof(ether_header)-sizeof(ip_header));//设定长度
//    //cout<<pudp_herder->len<<endl;
//    pudp_herder->checkl = 0;//设定检验和


//    strncpy(ethreqh.ifr_name, "eth0", IFNAMSIZ);
//    if(-1 == ioctl(sock_raw_fdh, SIOCGIFINDEX, &ethreqh))
//    {
//        perror("ioctl");
//        exit(-1);
//    }


//    bzero(&sllh, sizeof(sllh));
//    sllh.sll_ifindex = ethreqh.ifr_ifindex;

//    int read_len = 65;
//    u_int8_t buffer1[65] = {0};
//    u_int8_t ID = 4;
//    char *preimg = "1.png";
//    char *postimg = "2.png";
//    _wRECT preregion = {222,222,222,222};
//    _wRECT postregion = {333,333,333,333};
//    memcpy(buffer1,&ID,1);
//    memcpy(buffer1+1,(u_int8_t*)preimg,24);
//    memcpy(buffer1+25,(u_int8_t*)postimg,24);
//    memcpy(buffer1+49,(u_int8_t*)&preregion.left,2);
//    memcpy(buffer1+51,(u_int8_t*)&preregion.right,2);
//    memcpy(buffer1+53,(u_int8_t*)&preregion.top,2);
//    memcpy(buffer1+55,(u_int8_t*)&preregion.bottom,2);
//    memcpy(buffer1+57,(u_int8_t*)&postregion.left,2);
//    memcpy(buffer1+59,(u_int8_t*)&postregion.right,2);
//    memcpy(buffer1+61,(u_int8_t*)&postregion.top,2);
//    memcpy(buffer1+63,(u_int8_t*)&postregion.bottom,2);
//    memcpy(sendbufferh+42,buffer1,read_len);
//    int numm=0;
////    while(1){
//    cout<<"lalalalal"<<endl;
//        lenh = sendto(sock_raw_fdh, sendbufferh, read_len+42, 0 , (struct sockaddr *)&sllh, sizeof(sllh));
//        if(lenh == -1)
//        {
//            perror("sendto");
//        }
//        cout<<numm++<<" lalalallalalallaa"<<endl;
//        usleep(40000);
////    }
//    usleep(40000);

//}

////send IMU information
//#include <stdio.h>
//#include <stdlib.h>
//#include<iostream>
//#include <pcap.h>
//#include <opencv2/core/core.hpp>
//#include <opencv2/highgui/highgui.hpp>
//#include <opencv2/imgproc/imgproc.hpp>
//#include <opencv2/video/tracking.hpp>
//#include <string.h>
//#include <vector>
//#include <net/if.h>				//struct ifreq
//#include <sys/ioctl.h>			//ioctl¡¢SIOCGIFADDR
//#include <sys/socket.h>
//#include <netinet/ether.h>		//ETH_P_ALL
//#include <netpacket/packet.h>	//struct sockaddr_ll
//#include <unistd.h>
//#include <fstream>
//#include <sstream>
//#include <string>
//using namespace std;
//using namespace cv;

//#define BUFFER_SIZE 2

//struct _wRECT
//{
//    unsigned short left;
//    unsigned short right;
//    unsigned short top;
//    unsigned short bottom;
//};

//struct ip_header  //定义IP数据报头
//{
//    unsigned   char     ihl : 4;              //ip   header   length
//    unsigned   char     version : 4;          //version
//    u_char              tos;                //type   of   service
//    u_short             tot_len;            //total   length
//    u_short             id;                 //identification
//    u_short             frag_off;           //fragment   offset
//    u_char              ttl;                //time   to   live
//    u_char              protocol;           //protocol   type
//    u_short             check;              //check   sum
//    u_int               saddr;              //source   address
//    u_int               daddr;              //destination   address
//};


//struct tcphdr //定义TCP数据报头
//{
//    u_int16_t source;
//    u_int16_t dest;
//    u_int32_t seq;
//    u_int32_t ack_seq;
//    u_int16_t res1 : 4;
//    u_int16_t doff : 4;
//    u_int16_t fin : 1;
//    u_int16_t syn : 1;
//    u_int16_t rst : 1;
//    u_int16_t psh : 1;
//    u_int16_t ack : 1;
//    u_int16_t urg : 1;
//    u_int16_t res2 : 2;
//    u_int16_t window;
//    u_int16_t check;
//    u_int16_t urg_ptr;
//};



//struct udphdr
//{
//    u_int16_t source;         /* source port */
//    u_int16_t dest;           /* destination port */
//    u_int16_t len;            /* udp length */
//    u_int16_t checkl;
//    //u_int16_t check2;/* udp checksum */
//};

//char* uint_to_addr(u_int addr);

//u_int16_t in_cksumh(u_int16_t * addr, int len)
//{
//    int     nleft = len;
//    u_int32_t sum = 0;
//    u_int16_t *w = addr;
//    u_int16_t answer = 0;

//    /*
//    * Our algorithm is simple, using a 32 bit accumulator (sum), we add
//    * sequential 16 bit words to it, and at the end, fold back all the
//    * carry bits from the top 16 bits into the lower 16 bits.
//    */
//    while (nleft > 1) {
//        sum += *w++;
//        nleft -= 2;
//    }
//    /* mop up an odd byte, if necessary */
//    if (nleft == 1) {
//        *(unsigned char *)(&answer) = *(unsigned char *)w;
//        sum += answer;
//    }

//    /* add back carry outs from top 16 bits to low 16 bits */
//    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
//    sum += (sum >> 16);     /* add carry */
//    answer = ~sum;     /* truncate to 16 bits */
//    return (answer);
//}

//int main(int argc, char *argv[]){
//    int sock_raw_fdh = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
//    u_char sendbufferh[64] = { 0 };
//    u_char finishsign[4] = {"EOF"};
//    printf("%s\n",finishsign);
//    struct sockaddr_ll sllh;
//    struct ifreq ethreqh;
//    int lenh;

//    ether_header* pether_header = (ether_header*)sendbufferh;//以太网首部指针
//    ip_header* pip_herder = (ip_header*)(sendbufferh + sizeof(ether_header));//IP数据头指针
//    udphdr* pudp_herder = (udphdr*)(sendbufferh + sizeof(ether_header)+sizeof(ip_header));//UDP数据头指针

//    //针对以太网头部源地址进行赋值
//    pether_header->ether_shost[0] = 0x00;       //0x0 * 16 + 0x0;;
//    pether_header->ether_shost[1] = 0x04;       //0x2 * 16 + 0x1;
//    pether_header->ether_shost[2] = 0x4b;       //0x2 * 16 + 0x7;
//    pether_header->ether_shost[3] = 0xa5;       //0x2 * 16 + 0x3;
//    pether_header->ether_shost[4] = 0x42;       //0x7 * 16 + 0x2;
//    pether_header->ether_shost[5] = 0xb7;       //0xf * 16 + 0xe;

//    //针对以太网头部目的地址进行赋值
//    pether_header->ether_dhost[0] = 0x00;       //0x0 * 16 + 0x0;;
//    pether_header->ether_dhost[1] = 0x04;       //0x1 * 16 + 0xF;
//    pether_header->ether_dhost[2] = 0x4d;       //0xD * 16 + 0x0;
//    pether_header->ether_dhost[3] = 0xa5;       //0x1 * 16 + 0x6;
//    pether_header->ether_dhost[4] = 0x1a;       //0x6 * 16 + 0x3;
//    pether_header->ether_dhost[5] = 0xde;       //0x7 * 16 + 0x1;

//    //针对以太网协议进行赋值
//    pether_header->ether_type = htons(ETHERTYPE_IP);
//    if ((sizeof(ip_header) % 4) != 0)
//    {
//        printf("[IP Header error]/n");
//        //   return;
//    }

//    //构建IP数据头
//    pip_herder->ihl = sizeof(ip_header) / 4; //以4字节为单位
//    pip_herder->version = 4;//设定版本号
//    pip_herder->tos = 0; //设定类型
//    pip_herder->tot_len = htons(sizeof(sendbufferh)-sizeof(ether_header));//设定长度
//    pip_herder->id = htons(0x1000);//设定ID
//    pip_herder->frag_off = htons(0);//设定偏移量
//    pip_herder->ttl = 0x80;//设定TTL
//    pip_herder->protocol = IPPROTO_UDP;//设定协议类型
//    pip_herder->check = 0; //设定检验和
//    pip_herder->saddr = inet_addr("127.0.0.1"); //设定源地址
//    pip_herder->daddr = inet_addr("127.0.0.1");;//设定目的地址
//    pip_herder->check = in_cksumh((u_int16_t*)pip_herder, sizeof(ip_header)); //重新设定检验和

//    //构建UDP数据头;
//    pudp_herder->dest = htons(1024); //目的端口号
//    pudp_herder->source = htons(1024);//源端口号
//    pudp_herder->len = htons(sizeof(sendbufferh)-sizeof(ether_header)-sizeof(ip_header));//设定长度
//    //cout<<pudp_herder->len<<endl;
//    pudp_herder->checkl = 0;//设定检验和


//    strncpy(ethreqh.ifr_name, "eth0", IFNAMSIZ);
//    if(-1 == ioctl(sock_raw_fdh, SIOCGIFINDEX, &ethreqh))
//    {
//        perror("ioctl");
//        exit(-1);
//    }


//    bzero(&sllh, sizeof(sllh));
//    sllh.sll_ifindex = ethreqh.ifr_ifindex;

//    int read_len = 22;
//    u_int8_t buffer1[22] = {0};
//    u_int8_t ID = 5;
//    memcpy(buffer1,&ID,1);
//    fstream Intxt;
//    Intxt.open("/home/nvidia/data/1_1.txt");
//    assert(Intxt.is_open());
//    char linedata[200];
//    while(Intxt.getline(linedata,200)){

//        double data[9];
//        string out;
//        istringstream strline(linedata);
//        int i = 0;
//        while(strline>>out){
//            data[i]=atof(out.c_str());
//            i++;
//        }
//        u_int8_t frameID = (u_int8_t)round(data[0]);
//        int somenum = (int)round(data[1]);
//        int longtitude = (int)round(data[2]*10000000);
//        int latitude = (int)round(data[3]*10000000);
//        float height = data[4];
//        short az_angle = (short)round(data[5]*100);
//        short el_angle = (short)round(data[6]*100);
//        short roll_angle = (short)round(data[7]*100);
//        short fov_angle = (short)round(data[8]*100);

//        memcpy(buffer1+1,&frameID,1);
//        memcpy(buffer1+2,&longtitude,4);
//        memcpy(buffer1+6,&latitude,4);
//        memcpy(buffer1+10,&height,4);
//        memcpy(buffer1+14,&az_angle,2);
//        memcpy(buffer1+16,&el_angle,2);
//        memcpy(buffer1+18,&roll_angle,2);
//        memcpy(buffer1+20,&fov_angle,2);

//        memcpy(sendbufferh+42,buffer1,read_len);

//        static int numm=0;
//        cout<<"lalalalal"<<endl;
//        lenh = sendto(sock_raw_fdh, sendbufferh, read_len+42, 0 , (struct sockaddr *)&sllh, sizeof(sllh));
//        if(lenh == -1)
//        {
//            perror("sendto");
//        }
//        cout<<numm++<<" lalalallalalallaa"<<endl;
//        usleep(4000);
//    }
//    usleep(40000);

//}
