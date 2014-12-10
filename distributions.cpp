#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>

#include "defs.h"
#include "distributions.h"
#include "entropy.h"


void print_distribution (packet_distribution *distrib)
{
    int i;

    //for (i = 0; i < LENN; ++i) {
    //    printf("  %d|%.2f", i, element_frequency(distrib->pkt_len_class[i], distrib->count));
    //}

    //printf("  [c=%lu]", distrib->count);

    //printf("\n    Protocol Flag: ");
    //for (i = 0; i < PFLN; ++i) {
    //    printf(" \t%d(%f)", i, element_frequency(distrib->protocol_flag_class[i], distrib->count));
    //}
    //printf("\n");

}

// Average the relative entropies of all distributions in two classes
double normalized_relative_network_entropy (
        packet_distribution *distrib1,
        packet_distribution *distrib2,
        cli_opts *opts)
{
    double sum = 0;
    int num_used = 0;

    if (opts->use_dst_port_class) {
        num_used++;
        sum += relative_entropy (distrib1->count, distrib1->dst_port_class,
                distrib2->count, distrib2->dst_port_class, CDSTN);
    }

    if (opts->use_pkt_len) {
        num_used++;
        sum += relative_entropy (distrib1->count, distrib1->pkt_len_class,
                distrib2->count, distrib2->pkt_len_class, LENN);
    }

    if (opts->use_dst_port) {
        num_used++;
        sum += relative_entropy (distrib1->count, distrib1->dst_port,
                distrib2->count, distrib2->dst_port, DSTN);
    }

    if (opts->use_protocol_flag) {
        num_used++;
        sum += relative_entropy (distrib1->count, distrib1->protocol_flag_class,
                distrib2->count, distrib2->protocol_flag_class, PFLN);
    }

    if (num_used == 0) {
        return 0;
    }

    return sum / num_used;
}

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
unsigned short get_dst_port_class (unsigned short dst)
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

unsigned short get_most_active_dst_port_class(packet_distribution *distrib)
{
    int i, max = distrib->dst_port_class[0];
    for (i = 0; i < CDSTN; ++i) {
        if (distrib->dst_port_class[i] > distrib->dst_port_class[max]) {
            max = i;
        }
    }

    return max;
}

unsigned short get_most_active_pkt_len_class(packet_distribution *distrib)
{
    int i, max = 0;
    for (i = 0; i < LENN; ++i) {
        if (distrib->pkt_len_class[i] > distrib->pkt_len_class[max]) {
            max = i;
        }
    }

    return max;
}

// Split the packet length into well known classes
unsigned int get_packet_length_class (const struct pcap_pkthdr* pkthdr)
{
    unsigned short caplen = pkthdr->caplen;
    if (caplen <= 64) {
        return 0;
    } else if (caplen < 128) {
        return 1;
    } else if (caplen < 255) {
        return 2;
    } else if (caplen < 512) {
        return 3;
    } else if (caplen < 1024) {
        return 4;
    } else if (caplen < 1518) {
        return 5;
    } else {
        return 6;
    }
}

