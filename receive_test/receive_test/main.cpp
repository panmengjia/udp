
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
//#include <opencv2/core/core.hpp>
//#include <opencv2/highgui/highgui.hpp>
//#include <opencv2/imgproc/imgproc.hpp>
//#include <opencv2/video/tracking.hpp>
#include <string.h>
#include <vector>
#include <csignal>

using namespace std;
//using namespace cv;

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
  pcap_t * device = (pcap_t *)arg;
  static int id = 0;

  printf("id: %d\n", ++(id));
  printf("Packet length: %d\n", pkthdr->len);
  printf("Number of bytes: %d\n", pkthdr->caplen);
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));

  if((pkthdr->len==46)&&(*(packet+42)=='E')&&(*(packet+43)=='O')&&(*(packet+44)=='F')&&(*(packet+45)=='\0')){
       pcap_breakloop(device);
  }
  else /*if(pkthdr->caplen == 44)*/{
      char preimgpath[24];
      char postimgpath[24];
      cout <<" after filter data"<<endl;
      cout<<(int)*(packet+42)<<endl;
      cout<<(int)*(packet+43)<<endl;
//      printf("------------------3516dv300------------------\n");
//      memcpy(preimgpath,(char*)(packet+43),24);
//      memcpy(postimgpath,(char*)(packet+67),24);
//      cout<<preimgpath<<endl;
//      cout<<postimgpath<<endl;
//      cout<<(int)*(unsigned short*)(packet+91)<<endl;
//      cout<<(int)*(unsigned short*)(packet+93)<<endl;
//      cout<<(int)*(unsigned short*)(packet+95)<<endl;
//      cout<<(int)*(unsigned short*)(packet+97)<<endl;
//      cout<<(int)*(unsigned short*)(packet+99)<<endl;
//      cout<<(int)*(unsigned short*)(packet+101)<<endl;
//      cout<<(int)*(unsigned short*)(packet+103)<<endl;
//      cout<<(int)*(unsigned short*)(packet+105)<<endl;
//      cout.fill('0');
//      cout.flags(ios::fixed);
//      cout.precision(7);
//      cout<<(*(int*)(packet+44))/10000000.0<<endl;
//      cout<<(*(int*)(packet+48))/10000000.0<<endl;
//      cout.precision(2);
//      cout<<*(float*)(packet+52)<<endl;
//      cout<<(*(short*)(packet+56))/100.0<<endl;
//      cout<<(*(short*)(packet+58))/100.0<<endl;
//      cout<<(*(short*)(packet+60))/100.0<<endl;
//      cout<<(*(short*)(packet+62))/100.0<<endl;
  }
  printf("\n\n");
}


#define SAMPLE_PRT(fmt...)   \
    do {\
        printf("[%s]-%d: ", __FUNCTION__, __LINE__);\
        printf(fmt);\
    }while(0)


/*
接受双方网络设备名应该一致，在同一主机自发自收情况下，

*/
int main(int argc, char *argv[])
{

//#define ONEDEV

    char errBuf[PCAP_ERRBUF_SIZE];
#ifdef ONEDEV
    char * devStr;
    /* get a device */
    //得到可用的网络设备名指针
    //官方不推荐使用此方法
    //成功返回设备名指针（第一个合适的网络接口的字符串指针）
    devStr = pcap_lookupdev(errBuf);

    if(devStr)
    {
      SAMPLE_PRT("success: device: %s\n", devStr);
    }
    else
    {
      printf("error: %s\n", errBuf);
      exit(1);
    }

#else
    char* usedDevice;
    pcap_if_t *alldevs,*d; //结构体链表,链表结构体大小
    uint devCount=0;
    /* Retrieve the device list */
    //官方推荐使用此方法,use 'pcap_findalldevs' and use the first device
    if(pcap_findalldevs(&alldevs, errBuf) == -1)
    {
        SAMPLE_PRT("can't open file %s\n", errBuf);
        return -1;
    }

    if(alldevs->next->name==NULL)
    {
        printf("device is NULL\n");
        exit(-1);
    }
    else
    {
        printf("used dev : %s\n",alldevs->name);
    }

    /* Print the list */
    /*
    1. eno1  No description available
    2. wlp1s0  No description available
    3. any  Pseudo-device that captures on all interfaces
    4. lo  No description available
    5. nflog  Linux netfilter log (NFLOG) interface
    6. nfqueue  Linux netfilter queue (NFQUEUE) interface
    7. dbus-system  D-Bus system bus
    8. dbus-session  D-Bus session bus
    */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s ", ++devCount, d->name);//网络设备名
        if (d->description)
            printf(" %s\n", d->description);
        else
            printf(" No description available\n");
    }

    //判断网络设备名是否为0
    if(devCount==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    bpf_u_int32 netp = 0, maskp = 0;
    pcap_t * pcap_handle = NULL;
    int ret = 0;

    //获得网络号和掩码
    ret = pcap_lookupnet(alldevs->name, &netp, &maskp, errBuf);
    if(ret == -1)
    {
        printf(errBuf);
        exit(-1);
    }

    /*
    netp 192.168.1.0
    maskp 255.255.255.0
    */
    printf("netp %d.%d.%d.%d\n",*((uint8_t*)&netp+0),*((uint8_t*)&netp+1),*((uint8_t*)&netp+2),*((uint8_t*)&netp+3));
    printf("maskp %d.%d.%d.%d\n",*((uint8_t*)&maskp+0),*((uint8_t*)&maskp+1),*((uint8_t*)&maskp+2),*((uint8_t*)&maskp+3));

#endif
    /* open a device, wait until a packet arrives */
    /*
    device：网络接口的名字，为第一步获取的网络接口字符串（pcap_lookupdev() 的返回值 ），也可人为指定，如“eth0”。
    snaplen：捕获数据包的长度，长度不能大于 65535 个字节。
    promise：“1” 代表混杂模式，其它非混杂模式。什么为混杂模式，请看《原始套接字编程》。
    to_ms：指定需要等待的毫秒数，超过这个数值后，获取数据包的函数就会立即返回（这个函数不会阻塞，后面的抓包函数才会阻塞）。0 表示一直等待直到有数据包到来。
    ebuf：存储错误信息。
*/
//    pcap_t * device = pcap_open_live(alldevs->name, 65535, 1, 2000, errBuf);

//    if(!device)
//    {
//      printf("error: pcap_open_live(): %s\n", errBuf);
//      exit(1);
//    }
    pcap_t * device_handle = pcap_create(alldevs->name,errBuf);
    pcap_set_snaplen(device_handle,65535);
    pcap_set_promisc(device_handle,1);
    pcap_set_timeout(device_handle,0);
    pcap_set_immediate_mode(device_handle,1);
    pcap_activate(device_handle);
    const unsigned char *p_packet_content = NULL; // 保存接收到的数据包的起始地址
    struct pcap_pkthdr protocol_header;

    //编译 BPF 过滤规则
    //基于 BSD Packet Filter( BPF ) 结构
    //抓到的数据包往往很多，过滤掉不感兴趣的数据包
    /*
     * int pcap_compile(  pcap_t *p,
                    struct bpf_program *fp,
                    char *buf,
                    const char *optimize,
                    int,
                    bpf_u_int32 mask )
    p：pcap_open_live() 返回的 pcap_t 类型的指针
    fp：存放编译后的 bpf，应用过滤规则时需要用到这个指针
    buf：过滤条件
    optimize：是否需要优化过滤表达式
    mask：指定本地网络的网络掩码，不需要时可写 0

    */
    
    //过滤规则可以指定ip地址，但是对误码率好像没什么作用
    struct bpf_program filter;
    pcap_compile(device_handle, &filter, "src host 192.168.1.139", 1, 0);
    pcap_setfilter(device_handle, &filter);

    uint64_t noisePacCount=0;
    uint64_t needPacCount=0;
    for(uint64_t i=0;;++i)
    {
        printf("packet count :%d\n",i);
        //p_packet_content  所捕获数据包的地址
        p_packet_content = pcap_next(device_handle, &protocol_header); //2000ms 抓包阻塞时间
        printf("Capture Time is :%s",ctime((const time_t *)&protocol_header.ts.tv_sec)); // 时间
        printf("Packet caplen Lenght is :%d\n",protocol_header.caplen);
        printf("Packet len Lenght is :%d\n",protocol_header.len);   // 数据包的实际长度

        if(protocol_header.caplen==44)
        {
            printf("normal packet : %d\n",++needPacCount);
            printf("data %d %d\n",*(p_packet_content+42),*(p_packet_content+43));
        }
        else
        {
            printf("abnormal packet : %d\n",++noisePacCount);
            printf("-------------------noise packet---------------\n");
        }

    }


//    // 分析以太网中的 源mac、目的mac
//    struct ether_header *ethernet_protocol = NULL;
//    unsigned char *p_mac_string = NULL;         // 保存mac的地址，临时变量

//    ethernet_protocol = (struct ether_header *)p_packet_content;  //struct ether_header 以太网帧头部
//    p_mac_string = (unsigned char *)ethernet_protocol->ether_shost;//获取源mac
//    printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(p_mac_string+0),*(p_mac_string+1),*(p_mac_string+2),*(p_mac_string+3),*(p_mac_string+4),*(p_mac_string+5));

//    p_mac_string = (unsigned char *)ethernet_protocol->ether_dhost;//获取目的mac
//    printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(p_mac_string+0),*(p_mac_string+1),*(p_mac_string+2),*(p_mac_string+3),*(p_mac_string+4),*(p_mac_string+5));



    /*在使用wifi情况下，应该拔掉网线，否则eno1还是显示为第一个网络设备名 wlp1s0为第二网络设备名，*/
#ifdef ONEDEV
    pcap_t * device = pcap_create(devStr,errBuf);
#else
//    pcap_t * device = pcap_create(alldevs->name,errBuf);
#endif
//    pcap_set_snaplen(device,65535);
//    pcap_set_promisc(device,1);
//    pcap_set_timeout(device,0);
//    pcap_set_immediate_mode(device,1);
//    pcap_activate(device);

//    struct bpf_program filter;
//    pcap_compile(device, &filter, "src host 192.168.1.155", 1, 0);
//    pcap_setfilter(device, &filter);
//    /* wait loop forever */
//    pcap_set_timeout(device,1);
//    pcap_loop(device, -1, getPacket, (u_char*)device);
//    pcap_close(device);

    return 0;
}
