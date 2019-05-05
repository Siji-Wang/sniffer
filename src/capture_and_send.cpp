/*
=====================================================================
    Filename:capture_and_send.cpp
    Author： Fan Haishaung
    deScription: 网络数据包抓取转发类的类实现文件
=====================================================================
*/

#include"../include/capture_and_send.h"
#include"../include/sniffer.h"
#include"../include/headerType.h"

#include<time.h>
#include<string>

Capture_and_send::Capture_and_send()
{
  sniffer = new Sniffer;
  flag_run=true;
  Filename = NULL;
}

Capture_and_send::Capture_and_send(Sniffer *pSniffer,char *filename)
{
  sniffer = pSniffer;
  flag_run= true;
  Filename =filename;
}

Capture_and_send::~Capture_and_send(){
}

void Capture_and_send::setNetDev()
{
  sniffer-> findAllNetDevs();
  sniffer-> getNetDevInfo();
  sniffer->openNetDev(1);
}

void Capture_and_send::run()
{
  int res;
  struct tm *ltime;
  time_t local_tv_sec;
  char   timestr[16];

  int num =1;
  sniffer->sniffersData.clear();
  // printf("%s\n",Filename);

  if(Filename!=NULL){
    sniffer->openDumpFile(Filename);
  }

  while(flag_run==true&&(res=sniffer->captureOnce())>=0){
    if(res == 0){
      continue;
    }
    sniffer->saveCaptureData();

    tmp.protoInfo.init();

    tmp.Id=num;
    // num++;
    // printf("%d\n",num);
    if(num>10) break;
    tmp.strTime = ctime((const time_t *)&(sniffer->pkthdr)->ts.tv_sec);

    tmp.Length = sniffer->pkthdr->len;

    tmp.capLen = sniffer->pkthdr->caplen;

    eth_header *eh;
    ip_header *ih;
    udp_header *uh;
    tcp_header *th;
    unsigned short sport,dport;
    unsigned int ip_len,ip_all_len;
    unsigned char   *pByte;
    // std::string str="";
    // 获得 Mac头
    eh = (eth_header *)sniffer->packet;
    char buf1[20],buf2[20];

    sprintf(buf1,"%02x-%02x-%02x-%02x-%02x-%02x",eh->mac_dst[0],eh->mac_dst[1],eh->mac_dst[2],eh->mac_dst[3],eh->mac_dst[4],eh->mac_dst[5]);
    tmp.protoInfo.strDMac =tmp.protoInfo.strDMac+buf1;

    sprintf(buf2,"%02x-%02x-%02x-%02x-%02x-%02x",eh->mac_src[0],eh->mac_src[1],eh->mac_src[2],eh->mac_src[3],eh->mac_src[4],eh->mac_src[5]);
    tmp.protoInfo.strSMac =tmp.protoInfo.strSMac+buf2;

    //获得 IP 协议头
    ih = (ip_header *)(sniffer->packet+14);

    //获取 ip 首部长度
    ip_len=ih->ihl*4;

    char szSize[6];
    sprintf(szSize, "%u", ip_len);
    tmp.protoInfo.strHeadLength += szSize;
    tmp.protoInfo.strHeadLength += " bytes";

    ip_all_len = ntohs(ih->t_len);
    sprintf(szSize, "%u", ip_all_len);
    tmp.protoInfo.strLength += szSize;
    tmp.protoInfo.strLength += " bytes";

    char szSaddr[24], szDaddr[24];
    sprintf(szSaddr, "%d.%d.%d.%d", ih->ip_src[0], ih->ip_src[1], ih->ip_src[2], ih->ip_src[3]);
    sprintf(szDaddr, "%d.%d.%d.%d", ih->ip_dst[0], ih->ip_dst[1], ih->ip_dst[2], ih->ip_dst[3]);

    switch (ih->proto) {
        case TCP_SIG:
            tmp.strProto = "TCP";
            tmp.protoInfo.strNextProto += "TCP (Transmission Control Protocol)";
            tmp.protoInfo.strTranProto += "TCP 协议 (Transmission Control Protocol)";
            th = (tcp_header *)((unsigned char *)ih + ip_len);      // 获得 TCP 协议头
            sport = ntohs(th->src_port);                               // 获得源端口和目的端口
            dport = ntohs(th->dst_port);

            if (sport == FTP_PORT || dport == FTP_PORT) {
                tmp.strProto += " (FTP)";
                tmp.protoInfo.strAppProto += "FTP (File Transfer Protocol)";
            } else if (sport == TELNET_PORT || dport == TELNET_PORT) {
                tmp.strProto += " (TELNET)";
                tmp.protoInfo.strAppProto += "TELNET";
            } else if (sport == SMTP_PORT || dport == SMTP_PORT) {
                tmp.strProto += " (SMTP)";
                tmp.protoInfo.strAppProto += "SMTP (Simple Message Transfer Protocol)";
            } else if (sport == POP3_PORT || dport == POP3_PORT) {
                tmp.strProto += " (POP3)";
                tmp.protoInfo.strAppProto += "POP3 (Post Office Protocol 3)";
            } else if (sport == HTTPS_PORT || dport == HTTPS_PORT) {
                tmp.strProto += " (HTTPS)";
                tmp.protoInfo.strAppProto += "HTTPS (Hypertext Transfer "
                                                        "Protocol over Secure Socket Layer)";
            } else if (sport == HTTP_PORT || dport == HTTP_PORT ||
                     sport == HTTP2_PORT || dport == HTTP2_PORT) {
                tmp.strProto += " (HTTP)";
                tmp.protoInfo.strAppProto += "HTTP (Hyper Text Transport Protocol)";
                //tmp.protoInfo.strSendInfo = rawByteData.remove(0, 54);
            } else {
                tmp.protoInfo.strAppProto += "Unknown Proto";
            }
            break;
        case UDP_SIG:
            tmp.strProto = "UDP";
            tmp.protoInfo.strNextProto += "UDP (User Datagram Protocol)";
            tmp.protoInfo.strTranProto += "UDP 协议 (User Datagram Protocol)";
            uh = (udp_header *)((unsigned char *)ih + ip_len);      // 获得 UDP 协议头
            sport = ntohs(uh->src_port);                               // 获得源端口和目的端口
            dport = ntohs(uh->dst_port);
            pByte = (unsigned char *)ih + ip_len + sizeof(udp_header);

            if (sport == DNS_PORT || dport == DNS_PORT) {
                tmp.strProto += " (DNS)";
                tmp.protoInfo.strAppProto += "DNS (Domain Name Server)";
            } else if (sport == SNMP_PORT || dport == SNMP_PORT) {
                tmp.strProto += " (SNMP)";
                tmp.protoInfo.strAppProto += "SNMP (Simple Network Management Protocol)";
            } else if (*pByte == QQ_SIGN && (sport == QQ_SER_PORT || dport == QQ_SER_PORT)) {
                tmp.strProto += " (QQ)";
            } else {
                tmp.protoInfo.strAppProto += "Unknown Proto";
            }
            break;
        default:
            continue;
        }

    char szSPort[6], szDPort[6];
    sprintf(szSPort, "%d", sport);
    sprintf(szDPort, "%d", dport);

    tmp.strSIP = szSaddr;
    tmp.strSIP = tmp.strSIP + " : " + szSPort;
    tmp.strDIP = szDaddr;
    tmp.strDIP = tmp.strDIP + " : " + szDPort;

    tmp.protoInfo.strSIP   += szSaddr;
    tmp.protoInfo.strDIP   += szDaddr;
    tmp.protoInfo.strSPort += szSPort;
    tmp.protoInfo.strDPort += szDPort;
    if(sendPacket()==1){
      num++;
      // printf("num\n");
      sniffer->showSnifferData(tmp);
      sniffer->sniffersData.push_back(tmp);
    }
    // sniffer->showSnifferData();
  }
}



void Capture_and_send::stop()
{
  flag_run=true;
}

int Capture_and_send::sendPacket()
{
  struct pcap_pkthdr * pkthdr = sniffer->pkthdr;
  const u_char * packet = sniffer->packet;
  int i;
   eth_header *ethernet;
   sniffer_ip *ip;
   sniffer_tcp *tcp;
   udp_header *udp;
   u_char *payload;

  int size_ip, size_tcp, dst_PORT;
  int size_payload;
  char *dst_IP;
  int size_packet;
  uint8_t *data = (uint8_t *)malloc( 1500 * sizeof(uint8_t));

  ethernet = (eth_header*)(packet);


  ip = (sniffer_ip*)(packet + SIZE_ETHERNET);
  size_packet = ntohs(ip->t_len) + 14;
  size_ip = IP_HL(ip) * 4;
  if (size_ip < 20)
  {
      return -1;
  }
  // printf("%d\n",size_ip);
      // dst_IP = inet_ntoa(ip->ip_dst);

  ip->crc = 0;
  ip->crc = checksum((uint16_t *)ip,IP4_HDRLEN);
  tcp = (sniffer_tcp*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp) * 4;
  if (size_tcp < 20)
  {
  return -1;
  }
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
  size_payload = ntohs(ip->t_len) - (size_ip + size_tcp);

  udp = (udp_header*)(packet + SIZE_ETHERNET + size_ip);
  dst_PORT = ntohs(udp->dst_port);

  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof(udp_header));

  size_payload = ntohs(ip->t_len) - (size_ip + sizeof(udp_header));
  udp->src_port = htons(6000);
  udp->dst_port = htons(8000);
  udp->len = htons(UDP_HDRLEN + size_payload);
  printf("aaaa%d\n", SIZE_ETHERNET + size_ip + sizeof(udp_header));

  if (size_payload > 0)
  {
    sniffer->showSnifferData(tmp);
    printf("\nThe data captured:\n");
      for(int i=0;i<pkthdr->len;++i){
        printf("%02x ",packet[i]);
        if((i+1)%16==0){
          printf("\n");
        }
      }
      for(int j=1;j<95;++j){
        // printf("%c",*(payload+j));
        *(payload+j)='f';
      }

      int size_packet,size_ip1;
       eth_header *ethernet1;
       sniffer_ip *ip1;
       tcp_header *tcp1;
       udp_header *udp1;

      size_packet = ntohs(ip->t_len) + 14;

      ethernet1 = (eth_header*)(packet);
      memcpy(ethernet1->mac_src, eth_source, ETHER_ADDR_LEN);
      memcpy(ethernet1->mac_dst, eth_dest, ETHER_ADDR_LEN);

      ip1 = (sniffer_ip*)(packet + SIZE_ETHERNET);
      ip1->ip_src.s_addr = inet_addr(ip_source);
      ip1->ip_dst.s_addr = inet_addr(ip_dest);
      size_ip1 = IP_HL(ip1) * 4;
     // ip1->ttl = 255;
      ip1->crc = 0;
      ip1->crc = checksum((uint16_t *)ip1,IP4_HDRLEN);
      // printf(" IP new checksun: %d\n", ip1->crc);


      memcpy(data,payload,size_payload);

      udp1 = ( udp_header*)(packet + SIZE_ETHERNET + size_ip1);
      udp1->src_port = htons(6000);
      udp1->dst_port = htons(6000);
      udp1->len = htons(UDP_HDRLEN + size_payload);

      udp1->crc = udp4_checksum(ip1,udp1,data,size_payload);

      struct ifreq    dev_itf;
      const char     *dev_name = "wlp8s0";
      struct sockaddr_ll sdev,ddev;
      int fd;

      fd = socket(PF_PACKET, SOCK_RAW, htons(0x0800));  //�����׽���

      strncpy(dev_itf.ifr_name, dev_name, IFNAMSIZ);

      if(ioctl(fd, SIOCGIFINDEX, &dev_itf) == -1)
      {
           perror("ioctl - get device index");
           return -1;
      }

      sdev.sll_family         = AF_PACKET;
      sdev.sll_protocol       = htons(ETH_P_IP);
      sdev.sll_ifindex        = dev_itf.ifr_ifindex;
      sdev.sll_hatype         = ARPHRD_ETHER;
      sdev.sll_pkttype        = PACKET_HOST;
      sdev.sll_halen          = ETH_ALEN;
      memcpy(sdev.sll_addr, eth_source, ETH_ALEN);


      ddev.sll_family         = AF_PACKET;
      ddev.sll_protocol       = htons(ETH_P_IP);
      ddev.sll_ifindex        = dev_itf.ifr_ifindex;
      ddev.sll_hatype         = ARPHRD_ETHER;
      ddev.sll_pkttype        = PACKET_BROADCAST;
      ddev.sll_halen          = ETH_ALEN;
      memcpy(ddev.sll_addr, eth_dest, ETH_ALEN);


      if(bind(fd,(struct sockaddr *)&sdev, sizeof(sdev)) < 0)
      {
           perror("bind");
           close(fd);
           return -1;;
      }
  if(sendto(fd, packet, size_packet, 0, (struct sockaddr *)&ddev, sizeof(ddev)) == -1)
  {
      perror("send to");
      return -1;
  }
  printf("\nThe data sended:\n");
  for(int i=0;i<pkthdr->len;++i){
    printf("%02x ",packet[i]);
    if((i+1)%16==0){
      printf("\n");
    }
  }
  printf("\n\n");
  while(1){}
  }
  free (data);
  return 1;
}

void Capture_and_send::print_payload( u_char *payload, int len)
{
  int i;
  for (i = 0; i < len; i++)
  {
    if (isprint(*payload))
    printf("%c", *payload);
    else
    printf(".");

    payload++;
    if ((i+1) % 16 == 0)
    printf("\n");
  }
}

// Checksum function
uint16_t Capture_and_send::checksum (uint16_t *addr, int len)
{
  int nleft = len;
  int sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= sizeof (uint16_t);
  }

  if (nleft == 1) {
    *(uint8_t *) (&answer) = *(uint8_t *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t
Capture_and_send::udp4_checksum (sniffer_ip *iphdr,  udp_header *udphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  memcpy (ptr, &iphdr->ip_src.s_addr, sizeof (iphdr->ip_src.s_addr));
  ptr += sizeof (iphdr->ip_src.s_addr);
  chksumlen += sizeof (iphdr->ip_src.s_addr);

  memcpy (ptr, &iphdr->ip_dst.s_addr, sizeof (iphdr->ip_dst.s_addr));
  ptr += sizeof (iphdr->ip_dst.s_addr);
  chksumlen += sizeof (iphdr->ip_dst.s_addr);

  *ptr = 0; ptr++;
  chksumlen += 1;


  memcpy (ptr, &iphdr->proto, sizeof (iphdr->proto));
  ptr += sizeof (iphdr->proto);
  chksumlen += sizeof (iphdr->proto);


  memcpy (ptr, &udphdr->len, sizeof (udphdr->len));
  ptr += sizeof (udphdr->len);
  chksumlen += sizeof (udphdr->len);


  memcpy (ptr, &udphdr->src_port, sizeof (udphdr->src_port));
  ptr += sizeof (udphdr->src_port);
  chksumlen += sizeof (udphdr->src_port);


  memcpy (ptr, &udphdr->dst_port, sizeof (udphdr->dst_port));
  ptr += sizeof (udphdr->dst_port);
  chksumlen += sizeof (udphdr->dst_port);


  memcpy (ptr, &udphdr->len, sizeof (udphdr->len));
  ptr += sizeof (udphdr->len);
  chksumlen += sizeof (udphdr->len);

  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}
