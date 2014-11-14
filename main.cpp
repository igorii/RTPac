#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <set>

#include "defs.h"
#define SIZE_ETHERNET 14
#define CLASSN 587

typedef enum { P_TCP, P_UDP } Protocol;
typedef enum { TCP, TCPSYN, TCPRST, UDP } ProtocolFlag;

// Information distributions:
//    Protocol type (tcp, udp)   -- potentially include tcpack, tcprst, tcpsyn
//    Service (destination port) -- potentially break up into classes
//    Packet bytes

typedef struct s_packet_distribution {
    unsigned long long count;
    unsigned long dstport[CLASSN];
    //unsigned long      classes [4 * CLASSN];
} packet_distribution;

ProtocolFlag get_protocol_flag(Protocol proto, const struct sniff_tcp *tcp)
{
    if (proto == P_UDP) {
        return UDP;
    } else if (tcp->th_flags & TH_SYN) {
        return TCPSYN;
    } else if (tcp->th_flags & TH_RST) {
        return TCPRST;
    } else {
        return TCP;
    }
}

// 1) Divide packets into packet classes
//
//      First  Dimension  = TCP | TCP SYN | TCP RST | UDP
//      Second Dimension  = Port range
//          80                           -- HTTP
//          0     - 1023 (excluding 80)  -- Well Known Ports (divide into groups of 10)
//          1024  - 49151                -- Registered Ports (divide into groups of 100)
//          49152 - 65535                -- DynamicPrivate Ports
unsigned short get_dest_port_class (unsigned short dst)
{
    if (dst == 80) {
        return 0;
    } else if (dst < 1024) {
        return 4 + dst / 10;
    } else if (dst < 49124) {
        return 107 + (dst - 1024) / 100;
    } else if (dst < 49152) {
        return 2;
    } else {
        return 3;
    }
}

unsigned int get_packet_length_class (const struct pcap_pkthdr* pkthdr)
{
    unsigned short caplen = pkthdr->caplen;
    if (caplen <= 64) {
        return 1;
    } else if (caplen < 128) {
        return 2;
    } else if (caplen < 255) {
        return 3;
    } else if (caplen < 512) {
        return 4;
    } else if (caplen < 1024) {
        return 5;
    } else {
        return 6;
    }
}

unsigned short primary_to_offset (ProtocolFlag  proto)
{
    switch (proto) {
        case TCP:    return 0;
        case UDP:    return 1;
        case TCPSYN: return 2;
        case TCPRST: return 3;
    }
}

//unsigned long get_class (Protocol proto, unsigned short port, const struct sniff_tcp *tcp)
//{
//    unsigned short offset = primary_to_offset(get_protocol_flag(proto, tcp));
//    return (offset * CLASSN) + get_dest_port_class(port);
//}

void print_hex(const unsigned char *s)
{
    while (*s) {
        if (' ' <= *s && '~' >= *s) {
            printf("%c", *s);
        }
        *s++;
    }
    printf("\n");
}

void process_tcp_packet (
        const struct pcap_pkthdr* pkthdr,
        const u_char *packet,
        const struct sniff_ethernet *ethernet,
        const struct sniff_ip *ip,
        const u_int size_ip
        )
{
    const struct sniff_tcp *tcp;           /* The TCP header */
    const unsigned char *payload;          /* Packet payload */
    u_int size_tcp;

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    // TODO REMOVE THIS
    //   Skip SSH traffic for now to remove feedback loop
    if (22 == ntohs(tcp->th_sport) || 22 == ntohs(tcp->th_dport)) {
        return;
    }

    printf("   Protocol: TCP\n");
    printf("   From            : %s\n", inet_ntoa(ip->ip_src));
    printf("   To              : %s\n", inet_ntoa(ip->ip_dst));
    printf("   Src port        : %d\n", ntohs(tcp->th_sport));
    printf("   Dst port        : %d\n", ntohs(tcp->th_dport));
    printf("   Primary class   : %d\n", get_protocol_flag(P_TCP, tcp));
    printf("   Secondary class : %d\n", get_dest_port_class(ntohs(tcp->th_dport)));
    printf("   Length class    : %d\n", get_packet_length_class(pkthdr));
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    print_hex (payload);
}

void process_udp_packet () {
    printf("   Protocol: UDP\n");
    printf("   Primary class   : %d\n", get_protocol_flag(P_UDP, NULL));
}

void process_packet(
        u_char *mycustom,
        const struct pcap_pkthdr* pkthdr,
        const u_char* packet)
{
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip;             /* The IP header */
    u_int size_ip;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    switch(ip->ip_p) {
        case IPPROTO_TCP:
            process_tcp_packet(pkthdr, packet, ethernet, ip, size_ip);
            break;
        case IPPROTO_UDP:
            process_udp_packet();
            break;
        case IPPROTO_ICMP:
            return;
        case IPPROTO_IP:
            return;
        default:
            return;
    }
}

int main(int argc, char **argv)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;

    //distrib = (packet_distribution *) malloc ( sizeof (packet_distribution) );

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    int mycustom = 5;

    pcap_loop(descr, -1, process_packet, (u_char *)&mycustom);
    printf("Done\n");

    //free (distrib);
    return 0;
}
