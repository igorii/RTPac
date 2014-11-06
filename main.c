#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include "defs.h"

void print_hex(const char *s)
{
    while (*s) {
        if (' ' <= *s && '~' >= *s) {
            printf("%c", *s);
        }
        *s++;
    }
    printf("\n");
}

void proc_packet(u_char *useless, const struct pcap_pkthdr* pkthdr,
        const u_char* packet)
{

#define SIZE_ETHERNET 14

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip;             /* The IP header */
    const struct sniff_tcp *tcp;           /* The TCP header */
    const char *payload;                   /* Packet payload */
    u_int size_ip;
    u_int size_tcp;

    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

    //size_tcp = TH_OFF(tcp) * 4;
    //if (size_tcp < 20) {
    //    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    //    return;
    //}

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    //payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    //print_hex(payload);
}

int main(int argc,char **argv)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;

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

    pcap_loop(descr, -1, proc_packet, NULL);
    printf("Done\n");
    return 0;
}
