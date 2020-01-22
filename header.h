#include <typeinfo>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <fcntl.h>
#include <errno.h>
#include <resolv.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

void Attack();
void Find_user();
void GetMACaddr();

typedef struct eth_header
{
    u_int8_t Dest_hardware_addr[6];
    u_int8_t Source_hardware_addr[6];
    u_int16_t type;
} __attribute__((packed)) _eth_header, *ETH_H;

typedef struct ARP_header
{
    u_int16_t Hardware_type;
    u_int16_t Protocol_type;
    u_int8_t Hardware_address_length;
    u_int8_t Protocol_address_length;
    u_int16_t Operation_code; //1(ARP Request), 2(ARP Reply), 3(RARP Request), 4(RARP Reply)
    u_int8_t Source_hardware_address[6];
    u_int32_t Source_protocol_address;
    u_int8_t Destination_hardware_address[6];
    u_int32_t Destination_protocol_address;
} __attribute__((packed)) _arp_header, *ARP_H;

typedef struct IP_header
{
    u_char ip_v : 4, ip_hl : 4;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    u_int ip_src;
    u_int ip_dst;

} __attribute__((packed)) _ip_header, *IP_H;
