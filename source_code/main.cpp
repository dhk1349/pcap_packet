#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char* packet){
    //first six: dest-mac
    //next six: source-mac
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
}

int ether_next(const u_char* packet){
    //13th and 14th packet
    //printf("%x, %x", packet[0],packet[1]);
    if (packet[0]==0x08&&packet[1]==0x00)
        return 1;
    else {
        return -1;
    }
}

void print_IP(const u_char* packet){
    printf("%d.%d.%d.%d\n",packet[0],packet[1],packet[2],packet[3]);
}

int IP_next(const u_char* packet){//input should be 14+9
    if(packet[0]==6)
        return 1;
    else
        return -1;
}


void print_TCP(const u_char* packet){
    printf(" %d\n",packet[0]<<8|packet[1]);
}

int payload_len(const u_char* packet){
    //total length 2bytes
    //last 4bits among 1byte
    //tcp header length first 4bits
    //void payload_len(){IP header's total length- IP header's header length - tcp header's length}
    //just to make sure, IP and TCP header length is one digit long in 0x.
    int16_t temp=packet[14];
    temp=temp&0x0f;
    printf("tcp data length: %d\n",(packet[14+2]<<8)|packet[14+3]-4*(temp)-4*(packet[14+20+12]>>4));
    return (packet[14+2]<<8)|packet[14+3]-4*(temp)-4*(packet[14+20+12]>>4);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;//could not catch a pcket
    if (res == -1 || res == -2) break; //no more packet to receive
    printf("====================\n");
    printf("%u bytes captured\n", header->caplen);
    printf("D-mac: ");
    print_mac(&packet[0]);
    printf("S-mac: ");
    print_mac(&packet[6]);

    if(ether_next(&packet[12])!=1){
        printf("Not IPv4\n");
        continue;
    }

    printf("S-IP: ");
    print_IP(&packet[26]);
    printf("D-IP: ");
    print_IP(&packet[30]);

    if(IP_next(&packet[23])!=1){
        printf("Not TCP format\n");
        continue;
    }

    printf("S-port");
    print_TCP(&packet[34]);
    printf("D-port");
    print_TCP(&packet[36]);

    int len=payload_len(&packet[0]);
    printf("packet data: ");
    if(len>10)len=10;
    else if (len==0)printf("none");
    for(int i=0;i<len;i++)
        printf("%x ",packet[14+20+20+i]);
    printf("\n====================\n\n");
  }
  pcap_close(handle);
  return 0;
}
