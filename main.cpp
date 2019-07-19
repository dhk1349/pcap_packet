#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char* packet){
    //first six: dest-mac
    //next six: source-mac
    printf("%x:%x:%x:%x:%x:%x\n",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
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
    printf("%x.%x.%x.%x\n",packet[0],packet[1],packet[2],packet[3]);
}

int IP_next(const u_char* packet){//input should be 14+9
    if(packet[0]==6)
        return 1;
    else
        return -1;
}


void print_TCP(const u_char* packet){
    printf("%x %x\n",packet[0],packet[1]);
}

int Size_of_TCP_header(const u_char* packet){
    //tcp_start+12: data offset
    return packet[0];
}

int payload_len(const u_char* packet){
    printf("%x\n%x\n%x\n",(packet[14+2]<<8)|packet[14+3],(packet[14+0]),(packet[14+20+12]>>4));
    return ((packet[14+2]<<8)|packet[14+3])
    //total length 2bytes
    -(packet[14+0]>>4)-
    //last 4bits among 1byte
    (packet[14+20+12]>>4);
    //tcp header length first 4bits
}
//void payload_len(){IP header's total length- IP header's header length - tcp header's length}
//just to make sure, IP and TCP header length is one digit long in 0x.

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

    payload_len(&packet[0]);
  }

  pcap_close(handle);
  return 0;
}
