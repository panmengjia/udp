
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
  else{
      char preimgpath[24];
      char postimgpath[24];
      cout<<(int)*(packet+41)<<endl;
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


int main(int argc, char *argv[])
{
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;
    /* get a device */
    devStr = pcap_lookupdev(errBuf);

    if(devStr)
    {
      printf("success: device: %s\n", devStr);
    }
    else
    {
      printf("error: %s\n", errBuf);
      exit(1);
    }

    /* open a device, wait until a packet arrives */
//    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);

//    if(!device)
//    {
//      printf("error: pcap_open_live(): %s\n", errBuf);
//      exit(1);
//    }
    pcap_t * device = pcap_create(devStr,errBuf);
    pcap_set_snaplen(device,65535);
    pcap_set_promisc(device,1);
    pcap_set_timeout(device,0);
    pcap_set_immediate_mode(device,1);
    pcap_activate(device);

    struct bpf_program filter;
    pcap_compile(device, &filter, "src host 192.168.1.120", 1, 0);
    //只接收 tcp/udp 的端口是1024的数据包,
    // https://blog.csdn.net/a1009563517/article/details/47311813/
    pcap_compile(device, &filter, "src port 1024",1,0);
    pcap_setfilter(device, &filter);
    /* wait loop forever */
    pcap_set_timeout(device,1);
    pcap_loop(device, -1, getPacket, (u_char*)device);
    pcap_close(device);

    return 0;
}
