//main.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<stdint.h>
#include <stdbool.h>
#include "block.h"
#include "stc.h"

#define ETHER_TYPE_IP 0x0800
#define byte unsigned char


bool new_strstr(const char* payload, const char* pattern) {
    int pat_len = strlen(pattern);
    int payload_len = strlen(payload);
    if (strncmp(payload, "GET", 3) != 0) {
        return false;
    }
    for (int i = 0; i <= payload_len - pat_len; ++i) {
        if (strncmp(payload + i, pattern, pat_len) == 0) {
            return true;
        }
    }
    return false;
}


void printBuffer(byte *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n"); 
        }
    }
    printf("\n over!");
    printf("\n"); // 바이트 확인용 함수
}



int get_mac_addr(const char *iface, byte *mac) { // 스택오버플로우
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        perror("Socket error");
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Invalid MAC address");
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}
char * getIfToIP(char *ifName){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifName, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}





int main(int argc, char* argv[]) {

    if (argc != 3) { 
        printf("Usage : %s <interface> <pattern>\n",argv[0]);
        return 1;
    }
    byte myip[4]={0};
    const byte * dev = argv[1];
    byte * x = getIfToIP(argv[1]);
    inet_pton(AF_INET,x,myip);
    char errbuf[PCAP_ERRBUF_SIZE];

    byte src_mac[ETHER_ADDR_LEN];
    get_mac_addr(dev,src_mac);


    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    char* pattern = argv[2];
    printf("pattern is %s",pattern);


    struct pcap_pkthdr* header;
    struct libnet_ethernet_hdr* ethernet_hdr;
    struct libnet_ipv4_hdr* ip_hdr;
    struct libnet_tcp_hdr* tcp_hdr;
    const byte* packet;

    while (true) {
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue; 
        
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            exit(1);
        }

        ethernet_hdr = (struct libnet_ethernet_hdr*)packet;
        if (ntohs(ethernet_hdr->ether_type) == ETHER_TYPE_IP) {
            ip_hdr = (struct libnet_ipv4_hdr*)((byte*)ethernet_hdr + sizeof(struct libnet_ethernet_hdr));
            unsigned int ih_len = ip_hdr->ip_hl << 2;
            unsigned int pkt_len = ntohs(ip_hdr->ip_len)+ sizeof(struct libnet_ethernet_hdr);

            if (ip_hdr->ip_p == 6) {
                tcp_hdr = (struct libnet_tcp_hdr*)((byte*)ip_hdr + ih_len);
                unsigned int th_len = tcp_hdr->th_off <<2 ;
                unsigned int payload_len = ntohs(ip_hdr->ip_len) - (ih_len + th_len);

                if (payload_len){

                    char payload[payload_len + 1];
                    memset(payload, 0, payload_len + 1);
                    strncpy(payload, (byte*)tcp_hdr + th_len, payload_len);

                    if (new_strstr(payload, pattern)) {
                        rst(pcap, packet, ip_hdr, tcp_hdr, src_mac); //forward
                        fin(packet, ip_hdr, tcp_hdr,src_mac); //backward
                    }
                }
            }
        }
    }

    pcap_close(pcap);
    return 0;
}
