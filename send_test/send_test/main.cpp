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

 int main(int argc, char *argv[]){
    int sock_raw_fdh = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    u_char sendbufferh[44] = { 0 };
    u_char finishsign[4] = {"EOF"};
    printf("%s\n",finishsign);
    struct sockaddr_ll sllh;
    struct ifreq ethreqh;
    int lenh;

    ether_header* pether_header = (ether_header*)sendbufferh;//以太网首部指针
    ip_header* pip_herder = (ip_header*)(sendbufferh + sizeof(ether_header));//IP数据头指针
    udphdr* pudp_herder = (udphdr*)(sendbufferh + sizeof(ether_header)+sizeof(ip_header));//UDP数据头指针

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
    pip_herder->saddr = inet_addr("192.168.1.139"); //设定源地址
    pip_herder->daddr = inet_addr("192.168.1.139");//设定目的地址
    pip_herder->check = in_cksumh((u_int16_t*)pip_herder, sizeof(ip_header)); //重新设定检验和

    //构建UDP数据头;
    pudp_herder->dest = htons(1024); //目的端口号
    pudp_herder->source = htons(1024);//源端口号
    pudp_herder->len = htons(sizeof(sendbufferh)-sizeof(ether_header)-sizeof(ip_header));//设定长度
    //cout<<pudp_herder->len<<endl;
    pudp_herder->checkl = 0;//设定检验和


    strncpy(ethreqh.ifr_name, "wlp1s0", IFNAMSIZ);
    if(-1 == ioctl(sock_raw_fdh, SIOCGIFINDEX, &ethreqh))
    {
        perror("ioctl");
        exit(-1);
    }


    bzero(&sllh, sizeof(sllh));
    sllh.sll_ifindex = ethreqh.ifr_ifindex;

    int read_len = 2;
    u_int8_t buffer1[2] = {0,1};
    memcpy(sendbufferh+42,buffer1,read_len);
    int numm=0;
    while(1){
        lenh = sendto(sock_raw_fdh, sendbufferh, read_len+42, 0 , (struct sockaddr *)&sllh, sizeof(sllh));
        if(lenh == -1)
        {
            perror("sendto");
        }
        cout<<numm++<<" lalalallalalallaa"<<endl;
        printf("     %d ,%d\n",sendbufferh[42],sendbufferh[43]);
        usleep(40000);
    }
    usleep(40000);

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
