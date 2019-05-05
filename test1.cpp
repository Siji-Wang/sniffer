#include<stdio.h>
#include "./include/capture.h"
#include "./include/sniffer.h"
#include "./include/capture_qq.h"
#include "./include/capture_and_send.h"
int main(){
  Sniffer *s0=new Sniffer;
  Capture t0(s0,"./c_data/out4.pcap");
  t0.setNetDev();
  s0->consolePrint();
   printf("%s\n",s0->devStr);
  t0.run();
}
