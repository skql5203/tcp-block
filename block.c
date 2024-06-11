#include "block.h"
#include "stc.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pcap.h>

unsigned short CheckSum(unsigned short* buffer, int size) { //from google searching
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
        cksum += *(unsigned short*)buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

void rst(pcap_t* pcap, const unsigned char* packet, struct libnet_ipv4_hdr* ip_hdr, struct libnet_tcp_hdr* tcp_hdr, unsigned char* src_mac) {
    unsigned int ih_len = ip_hdr->ip_hl << 2;
    unsigned int plen = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_tcp_hdr)+ih_len;
    unsigned char* new_pack = (unsigned char*)calloc(1, plen);
    if (!new_pack) {
        perror("calloc failed");
        return;
    }

    memcpy(new_pack, packet, plen);

    struct libnet_ethernet_hdr* ethernet_hdr = (struct libnet_ethernet_hdr*)new_pack;
    struct libnet_ipv4_hdr* new_ip_hdr = (struct libnet_ipv4_hdr*)(new_pack + sizeof(struct libnet_ethernet_hdr));
    struct libnet_tcp_hdr* new_tcp_hdr = (struct libnet_tcp_hdr*)((char*)new_ip_hdr + ih_len);

    memcpy(ethernet_hdr->ether_shost, src_mac, ETHER_ADDR_LEN);

    new_ip_hdr->ip_sum = 0;
    new_tcp_hdr->th_sum = 0;

    new_ip_hdr->ip_len = htons(ih_len + sizeof(struct libnet_tcp_hdr));
    new_tcp_hdr->th_off = sizeof(struct libnet_tcp_hdr) / 4;
    new_tcp_hdr->th_seq = htonl(ntohl(tcp_hdr->th_seq) + ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl*4 + tcp_hdr->th_off * 4));
    new_tcp_hdr->th_flags = TH_ACK | TH_RST;

    check_s chk_addr;
    memset(&chk_addr, 0, sizeof(check_s));
    chk_addr.s_addr = new_ip_hdr->ip_src.s_addr;
    chk_addr.d_address = new_ip_hdr->ip_dst.s_addr;
    chk_addr.pro = IPPROTO_TCP;
    chk_addr.tl = htons(sizeof(struct libnet_tcp_hdr));

    unsigned int tcp_checksum = CheckSum((unsigned short*)new_tcp_hdr, sizeof(struct libnet_tcp_hdr)) + CheckSum((unsigned short*)&chk_addr, sizeof(check_s));
    new_tcp_hdr->th_sum = (tcp_checksum & 0xffff) + (tcp_checksum >> 16);
    new_ip_hdr->ip_sum = CheckSum((unsigned short*)new_ip_hdr, ih_len);

    if (pcap_sendpacket(pcap, (unsigned char *)(new_pack), plen)) {
        fprintf(stderr, "pcap_sendpacket return %s", pcap_geterr(pcap));
    }

    free(new_pack);
}

void fin(const unsigned char* packet, struct libnet_ipv4_hdr* ip_hdr, struct libnet_tcp_hdr* tcp_hdr,byte* src_mac) {
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        perror("socket failed");
        return;
    }

    int optval = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("setsockopt failed");
        close(raw_sock);
        return;
    }

    struct sockaddr_in sock_addr;
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = tcp_hdr->th_sport;
    sock_addr.sin_addr.s_addr = ip_hdr->ip_src.s_addr;

    const char* new_tcp_data = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
    unsigned short ethernet_len=sizeof(struct libnet_ethernet_hdr);
    unsigned short ip_hdr_len = sizeof(struct libnet_ipv4_hdr);
    unsigned short tcp_hdr_len = sizeof(struct libnet_tcp_hdr);
    unsigned short new_tcp_data_len = strlen(new_tcp_data);
    unsigned short total_len =  tcp_hdr_len + new_tcp_data_len + ip_hdr_len;

    unsigned char* new_pack = (unsigned char*)calloc(1, ethernet_len+total_len);
    if (!new_pack) {
        perror("calloc failed");
        close(raw_sock);
        return;
    }
    struct libnet_ethernet_hdr* ethernet_hdr = (struct libnet_ethernet_hdr*)new_pack;
    struct libnet_ipv4_hdr* new_ip_hdr = (struct libnet_ipv4_hdr*)(new_pack + sizeof(struct libnet_ethernet_hdr));
    struct libnet_tcp_hdr* new_tcp_hdr = (struct libnet_tcp_hdr*)((unsigned char*)new_ip_hdr + ip_hdr_len);

    memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, src_mac, ETHER_ADDR_LEN);
    
    new_ip_hdr->ip_hl = ip_hdr_len / 4;
    new_ip_hdr->ip_v = 4;
    new_ip_hdr->ip_len = htons(total_len);
    new_ip_hdr->ip_ttl = 128;
    new_ip_hdr->ip_p = IPPROTO_TCP;
    new_ip_hdr->ip_src.s_addr = ip_hdr->ip_dst.s_addr;
    new_ip_hdr->ip_dst.s_addr = ip_hdr->ip_src.s_addr;

    memcpy(new_pack +ethernet_len+ ip_hdr_len + tcp_hdr_len, new_tcp_data, new_tcp_data_len);
    new_tcp_hdr->th_sport = tcp_hdr->th_dport;
    new_tcp_hdr->th_dport = tcp_hdr->th_sport;
    new_tcp_hdr->th_seq = tcp_hdr->th_ack;
    new_tcp_hdr->th_ack = htonl(ntohl(tcp_hdr->th_seq) + (ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4 + (tcp_hdr->th_off * 4))));
    new_tcp_hdr->th_off = tcp_hdr_len / 4;
    new_tcp_hdr->th_flags = TH_ACK | TH_FIN;
    new_tcp_hdr->th_win = tcp_hdr->th_win;
    
    check_s chk_addr;
    memset(&chk_addr, 0, sizeof(check_s));
    chk_addr.s_addr = new_ip_hdr->ip_src.s_addr;
    chk_addr.d_address = new_ip_hdr->ip_dst.s_addr;
    chk_addr.pro = IPPROTO_TCP;
    chk_addr.tl = htons(tcp_hdr_len + new_tcp_data_len);

    unsigned int tcp_checksum = CheckSum((unsigned short*)new_tcp_hdr, tcp_hdr_len + new_tcp_data_len) + CheckSum((unsigned short*)&chk_addr, sizeof(check_s));
    new_tcp_hdr->th_sum = (tcp_checksum & 0xffff) + (tcp_checksum >> 16);
    new_ip_hdr->ip_sum = CheckSum((unsigned short*)new_ip_hdr, ip_hdr_len);


    /*if (connect(raw_sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
        perror("connect failed");
        close(raw_sock);
        return;
    }
    if (send(raw_sock, new_pack, ethernet_len+total_len, 0) < 0) {
        perror("Send failed");
    }*/

    if (sendto(raw_sock, new_ip_hdr, total_len, 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
        perror("Send failed");
    }

    free(new_pack);
    close(raw_sock);
}



