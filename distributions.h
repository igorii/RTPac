#ifndef DISTRIBUTIONS_H
#define DISTRIBUTIONS_H

#include "cli_opts.h"

#define CDSTN 587
#define DSTN 65536
#define LENN 7
#define PFLN 4

typedef enum { P_TCP, P_UDP } Protocol;
typedef enum { TCP, TCPSYN, TCPRST, UDP } ProtocolFlag;

// Information distributions:
//    Service (destination port) -- potentially break up into classes
//    Packet bytes               -- see length_class
//    Protocol type (tcp, udp)   -- potentially include tcpack, tcprst,
//                                  tcpsyn (see get_protocol_flag)
typedef struct s_packet_distribution {
    unsigned long count;
    unsigned long dst_port_class[CDSTN];
    unsigned long dst_port[DSTN];
    unsigned long pkt_len_class[LENN];
    unsigned long protocol_flag_class[PFLN];
    double mean;
    double standard_deviation;
    unsigned long max_count;
    struct timeval start_time;
    struct timeval end_time;
} packet_distribution;

void print_distribution (packet_distribution *distrib);
ProtocolFlag get_protocol_flag(Protocol proto, const struct sniff_tcp *tcp);
unsigned short get_dst_port_class (unsigned short dst);
unsigned short get_most_active_dst_port_class(packet_distribution *distrib);
unsigned short get_most_active_pkt_len_class(packet_distribution *distrib);
unsigned int get_packet_length_class (const struct pcap_pkthdr* pkthdr);
double normalized_relative_network_entropy (
        packet_distribution *distrib1,
        packet_distribution *distrib2,
        cli_opts *opts);

#endif
