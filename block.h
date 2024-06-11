//block.h
#ifndef BLOCK_H
#define BLOCK_H
#include <pcap.h>
#include "stc.h"
#define byte unsigned char

unsigned short CheckSum(unsigned short* buffer, int size);
void rst(pcap_t* handle, const byte* packet, struct libnet_ipv4_hdr* ip_hdr, struct libnet_tcp_hdr* tcp_hdr,byte * src_mac);
void fin(const byte* packet, struct libnet_ipv4_hdr* ip_hdr, struct libnet_tcp_hdr* tcp_hdr,byte *src_mac);

#endif