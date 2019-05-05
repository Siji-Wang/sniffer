/*
=====================================================================
    Filename:capture_and_send.h
    Author： Fan Haishaung
    deScription: 网络数据包抓取类的类声明文件
=====================================================================
*/

#ifndef CAPTURE_AND_SEND_H_
#define CAPTURE_AND_SEND_H_

#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <linux/if_packet.h>

#include"../include/sniffer.h"
#include"../include/headerType.h"


struct sniffer_ip
{
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
  unsigned char ser_type; //服务类型(1 Byte)
  unsigned short t_len; //总长 (2 Bytes)
  unsigned short iden; //标识 (2 Bytes)
  unsigned short flags:3; //标志位(3 bites)
  unsigned short offset:13; //片偏移量(13 bites)
  unsigned char ttl=5000000; //生存时间 (1 Byte)
  unsigned char proto; //协议 ( 1 Byte)
  unsigned short crc; //首部校验和 (2 Bytes)
  struct  in_addr ip_src,ip_dst;
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct sniffer_tcp
{
	unsigned short	src_port;				// 源端口号(2 Bytes)
	unsigned short	dst_port;				// 目的端口号(2 Bytes)
	unsigned int	tcp_seq;				// 序列号 (4 Bytes)
	unsigned int	tcp_ack;				// 确认号 (4 Bytes)
  u_char  th_offx2;               /* data offset, rsvd */
	unsigned char	reseverd_2:2;		// 保留6位中的2位(2 bites)
	unsigned char	flag:6;				// 6位标志 (6 bites)
	unsigned short	wnd_size;			// 16位窗口大小 (2 Bytes)
	unsigned short	chk_sum;			// 16位TCP检验和(2 Bytes)
	unsigned short	urgt_p;				// 16为紧急指针(s Bytes)
};
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)

class Capture_and_send
{
  public:
    Capture_and_send();
    Capture_and_send(Sniffer* pSniffer,char *filename);
    ~Capture_and_send();
    void setNetDev();//设置设备信息
    void run();//开始抓取数据
    void stop();//停止抓取数据
    // char** eth_source={0xe4,0xf8,0x9c,0xf7,0x6d,0x86};
    // char** eth_dest={0x18,0x3d,0xa2,0xd4,0xf2,0xbf};
    u_char eth_source[ETH_ALEN]={0xe4,0xf8,0x9c,0xf7,0x6d,0x86};
    u_char eth_dest[ETH_ALEN]={0x18,0x3d,0xa2,0xd4,0xf2,0xbf};
    char *ip_source = "192.168.1.110";
    char *ip_dest = "192.168.1.108";
  private:
    Sniffer *sniffer;
    bool flag_run;
    char *Filename;
    SnifferData tmp;
    int sendPacket();

    void print_payload( u_char *payload, int len);

    uint16_t checksum (uint16_t *addr, int len);

    uint16_t udp4_checksum (sniffer_ip *iphdr,  udp_header *udphdr, uint8_t *payload, int payloadlen);
};

#endif //CAPTURE_H_
