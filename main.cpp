#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <set>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include "defs.h"
#include "entropy.h"
#include "cli_opts.h"

#define SIZE_ETHERNET 14
#define CDSTN 587
#define DSTN 65536
#define LENN 7
#define PFLN 4

// TODO move this into the user data passed to pcap loop
pcap_t* descr;

// @see "A Network Anomaly Detection Method Based on Relative Entropy Theory" -- Ya-ling Zhang, Zhao-gou Han, Jiao-xia Ren

typedef enum { P_TCP, P_UDP } Protocol;
typedef enum { TCP, TCPSYN, TCPRST, UDP } ProtocolFlag;

// Information distributions:
//    Protocol type (tcp, udp)   -- potentially include tcpack, tcprst, tcpsyn (see get_protocol_flag)
//    Service (destination port) -- potentially break up into classes
//    Packet bytes               -- see length_class
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

typedef struct s_callback_data {
    packet_distribution window;
    packet_distribution baseline;
} callback_data;

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
    //sum += relative_entropy (distrib1->count, distrib1->pkt_len_class,
    //        distrib2->count, distrib2->pkt_len_class, LENN);
    //sum += relative_entropy (distrib1->count, distrib1->dst_port,
    //        distrib2->count, distrib2->dst_port, DSTN);
    //sum += relative_entropy (distrib1->count, distrib1->protocol_flag_class,
    //        distrib2->count, distrib2->protocol_flag_class, PFLN);
    sum += relative_entropy (distrib1->count, distrib1->dst_port_class,
            distrib2->count, distrib2->dst_port_class, CDSTN);
    return sum / 1;
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

// Print only printable charcters in a string
void print_hex(const unsigned char *s)
{
    while (*s) {
        if (10 == (unsigned char) *s || (' ' <= *s && '~' >= *s)) {
            printf("%c", *s);
        }
        *s++;
    }
    printf("\n");
}

// Given a tcp packet, update the distribution information `distrib` with the correct classes
void process_tcp_packet (
        packet_distribution *distrib,
        const struct pcap_pkthdr* pkthdr,
        const u_char *packet,
        const struct sniff_ethernet *ethernet,
        const struct sniff_ip *ip,
        const u_int size_ip)
{
    const struct sniff_tcp *tcp;           /* The TCP header */
    const unsigned char *payload;          /* Packet payload */
    u_int size_tcp;

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        return;
    }

    // TODO REMOVE THIS -- Skip SSH traffic for now to remove feedback loop
    if (22 == ntohs(tcp->th_sport) || 22 == ntohs(tcp->th_dport)) {
        return;
    }

    distrib->count++;
    distrib->dst_port            [ ntohs(tcp->th_dport)                       ]++;
    distrib->dst_port_class      [ (get_dst_port_class(ntohs(tcp->th_dport))) ]++;
    distrib->pkt_len_class       [ (get_packet_length_class(pkthdr))          ]++;
    distrib->protocol_flag_class [ (get_protocol_flag(P_TCP, tcp))            ]++;

    // TODO Make this cleaner (or remove?) to satisfy statistical output goals
    //     - possible use ncurses to update view with updating distributions showing
    //       contrast between trained distributions and current window distributions
    //     - if using ncurses, or some real-time view, move this to process_packet
    //       to avoid duplicating in udp()
    //    printf("   Protocol: TCP\n");
    //    printf("   From            : %s\n", inet_ntoa(ip->ip_src));
    //    printf("   To              : %s\n", inet_ntoa(ip->ip_dst));
    //    printf("   Src port        : %d\n", ntohs(tcp->th_sport));
    //    printf("   Dst port        : %d\n", ntohs(tcp->th_dport));
    //    printf("   Primary class   : %d\n", get_protocol_flag(P_TCP, tcp));
    //    printf("   Secondary class : %d\n", get_dst_port_class(ntohs(tcp->th_dport)));
    //    printf("   Length class    : %d\n", get_packet_length_class(pkthdr));
    //
    //
    //    printf("   Most active dst : %d (%f)\n",
    //            get_most_active_dst_port_class(distrib),
    //            element_frequency(distrib->dst_port_class[
    //                  get_most_active_dst_port_class(distrib)
    //                ], distrib->count));
    //
    //    printf("   Most active len : %d (%f)\n",
    //            get_most_active_pkt_len_class(distrib),
    //            element_frequency(distrib->pkt_len_class[
    //                  get_most_active_pkt_len_class(distrib)
    //                ], distrib->count));
    //
    //    printf("   Dst Class Entropy        : %f\n",
    //            entropy_of_distribution(distrib->count,
    //                distrib->dst_port_class, CDSTN));
    //
    //    printf("   Pkt Length Entropy       : %f\n",
    //            entropy_of_distribution(distrib->count,
    //                distrib->pkt_len_class, LENN));
    //
    //    printf("   Protocol Flag  Entropy   : %f\n",
    //            entropy_of_distribution(distrib->count,
    //                distrib->protocol_flag_class, PFLN));
    //
    //    printf("   Destination Port Entropy : %f\n",
    //            entropy_of_distribution(distrib->count,
    //                distrib->dst_port, DSTN));
    //
    //    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    //print_hex (payload);
}

// Given a udp packet, update the distribution information `distrib` with the correct classes
void process_udp_packet (
        packet_distribution *distrib,
        const struct pcap_pkthdr* pkthdr,
        const u_char *packet,
        const struct sniff_ethernet *ethernet,
        const struct sniff_ip *ip,
        const u_int size_ip)
{
    const struct sniff_udp *udp;           /* The UDP header */
    const unsigned char *payload;          /* Packet payload */
    u_int size_udp;
    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

    distrib->count++;
    distrib->dst_port            [ ntohs(udp->dport)                     ]++;
    distrib->dst_port_class      [ get_dst_port_class(ntohs(udp->dport)) ]++;
    distrib->pkt_len_class       [ get_packet_length_class(pkthdr)       ]++;
    distrib->protocol_flag_class [ get_protocol_flag(P_UDP, NULL)        ]++;
}

// Capture a packet from the network, switch on its protocol, and classify its distributoin information.
// Finally, update the view with the new distributoin information.
void process_packet(
        u_char *data,
        const struct pcap_pkthdr* pkthdr,
        const u_char* packet)
{
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip;             /* The IP header */
    u_int size_ip;
    packet_distribution *distrib;

    // Obtain the running distributions from the data (@see s_packet_distribution)
    distrib = (packet_distribution *) data;

    if (distrib->count == 0) {
        memcpy(&distrib->start_time, &pkthdr->ts, sizeof(struct timeval));
    }

    // Ensure correct packet length (throw away invalid packets)
    // TODO - should the distribution of correct to incorrect packets be logged?
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        //    printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    // Dispatch to the correct protocol handler
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            process_tcp_packet(distrib, pkthdr, packet, ethernet, ip, size_ip);
            break;
        case IPPROTO_UDP:
            //process_udp_packet(distrib, pkthdr, packet, ethernet, ip, size_ip);
            break;
        case IPPROTO_ICMP:
            return;
        case IPPROTO_IP:
            return;
        default:
            return;
    }

    // Stop capturing at the window limit
    memcpy(&distrib->end_time, &pkthdr->ts, sizeof(struct timeval));
    if (distrib->count >= distrib->max_count) {
        pcap_breakloop(descr);
    }
}

double sanity_check_probabilities (
        unsigned long classes,
        unsigned long count,
        unsigned long *distrib)
{
    int i;
    double sum = 0;
    for (i = 0; i < classes; ++i)
        sum += element_frequency (distrib[i], count);

    return sum;
}

unsigned char sanity_check_distribution (packet_distribution *distrib)
{
    // All sums should be 1
    return (0.001 > 1 - sanity_check_probabilities (PFLN,
                distrib->count, distrib->protocol_flag_class) &&
            0.001 > 1 - sanity_check_probabilities (LENN,
                distrib->count, distrib->pkt_len_class));
}

void relative_entropy_of_distributions (packet_distribution *distrib1, packet_distribution *distrib2)
{
    printf("Dst Class difference    : %f\n"
            "Dst Port difference     : %f\n"
            "Packet Len difference   : %f\n"
            "Protocol flag difference: %f\n",
            relative_entropy (distrib1->count, distrib1->dst_port_class,
                distrib2->count, distrib2->dst_port_class, CDSTN),
            relative_entropy (distrib1->count, distrib1->dst_port,
                distrib2->count, distrib2->dst_port, DSTN),
            relative_entropy (distrib1->count, distrib1->pkt_len_class,
                distrib2->count, distrib2->pkt_len_class, LENN),
            relative_entropy (distrib1->count, distrib1->protocol_flag_class,
                distrib2->count, distrib2->protocol_flag_class, PFLN));
}

double mean (double *distribution, int num)
{
    double sum = 0;
    int i;

    for (i = 0; i < num; ++i)
        sum += distribution[i];

    return sum / num;
}

double square_difference (double a, double b)
{
    return pow(a - b, 2);
}

double std_dev(double *distribution, int num)
{
    double mean_ = 0;
    double squares[num];
    int i;

    mean_ = mean(distribution, num);

    for (i = 0; i < num; ++i)
        squares[i] = square_difference (distribution[i], mean_);

    return mean(squares, num);
}

void capture_regular_deviation(packet_distribution *baseline, int num_windows, int window_size, cli_opts *opts)
{
    int i;
    double window_history[num_windows];
    unsigned char distribution_correct;
    packet_distribution window;

    for (i = 0; i < num_windows; ++i) {
        bzero(&window, sizeof (packet_distribution));
        window.max_count = window_size;
        printf ("\nBeginning window %d capture of baseline...\n\n", i);
        pcap_loop(descr, -1, process_packet, (u_char *)&window);

        // Sanity check, ensure all probability vectors sum to 1
        //        Kullback-Leibler divergence is only defined at this point
        distribution_correct = sanity_check_distribution(&window);
        print_distribution(&window);
        if (!distribution_correct) {
            fprintf(stderr, "Window distribution is not correct\n");
            print_distribution(&window);
            exit(1);
        } else {
            // The distribution is correct in this case, so proceed...
            // Calculate the relative entropy of the two distributions
            window_history[i] = normalized_relative_network_entropy(&window, baseline, opts);
        }
    }

    // Store the standard deviation in the given distribution
    baseline->mean               = mean(window_history, num_windows);
    baseline->standard_deviation = std_dev(window_history, num_windows);
}

pcap_t *open_live() {
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find a device to sniff
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    // Open the interface
    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    pcap_setdirection(descr, PCAP_D_IN);
    return descr;
}

pcap_t *open_offline(const char * file) {
    char errbuf[PCAP_ERRBUF_SIZE];

    descr = pcap_open_offline(file, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    pcap_setdirection(descr, PCAP_D_IN);
    return descr;
}

packet_distribution *new_distribution() {
    packet_distribution *distribution;
    distribution = (packet_distribution *) malloc ( sizeof (packet_distribution) );
    bzero(distribution, sizeof (packet_distribution));
    return distribution;
}



int main(int argc, char **argv)
{
    packet_distribution *baseline_distribution;
    packet_distribution *window_distribution;
    double nrne;
    double std;
    unsigned char distribution_correct;
    int num_attacks = 0;
    cli_opts opts;

    parse_args(argc, argv, &opts);

    // Initialize the running distribution
    baseline_distribution = new_distribution();
    window_distribution   = new_distribution();

    if (opts.live) {
        descr = open_live();
    } else {
        descr = open_offline(opts.training_file);
    }

    // Begin capturing packets for baseline behaviour
    baseline_distribution->max_count = opts.max_baseline_count;
    pcap_loop(descr, -1, process_packet, (u_char *)baseline_distribution);
    distribution_correct = sanity_check_distribution(baseline_distribution);
    if (!distribution_correct) {
        fprintf(stderr, "Baseline distribution is not correct\n");
        exit(1);
    }

    pcap_close(descr);

    if (opts.live) {
        descr = open_live();
    } else {
        descr = open_offline(opts.training_file);
    }

    capture_regular_deviation(baseline_distribution,
            floor(baseline_distribution->count / opts.max_window_count),
            opts.max_window_count,
            &opts);

    printf ("\nFinished capturing baseline behaviour.\n\n");
    print_distribution(baseline_distribution);
    printf("Regular deviation: %f\n\n", baseline_distribution->standard_deviation);

    pcap_close(descr);

    if (opts.live) {
        descr = open_live();
    } else {
        descr = open_offline(opts.attack_file);
    }

    // Begin capturing window distributions and comparing every `window_size_in_pkts` many captures
    for (;;) {

        // Reset the window distribution
        bzero(window_distribution, sizeof (packet_distribution));
        window_distribution->max_count = opts.max_window_count;
        pcap_loop(descr, -1, process_packet, (u_char *)window_distribution);

        // If we have finished reading the file, break out of the loop
        if (window_distribution->count < window_distribution->max_count) {
            break;
        }

        // Sanity check, ensure all probability vectors sum to 1
        //        Kullback-Leibler divergence is only defined at this point
        distribution_correct = sanity_check_distribution(window_distribution);
        if (!distribution_correct) {
            fprintf(stderr, "Window distribution is not correct, ignoring window\n");
            print_distribution(window_distribution);
        } else {
            // The distribution is correct in this case, so proceed...
            // Calculate the relative entropy of the two distributions
            nrne = normalized_relative_network_entropy(window_distribution, baseline_distribution, &opts);
            std  = square_difference(nrne, baseline_distribution->mean);

            if (std > (20 * baseline_distribution->standard_deviation)) {
                printf("\n[!!] ANOMALOUS USAGE DETECTED : %s",
                        ctime((const time_t*)&window_distribution->start_time.tv_sec));
                fprintf(stderr, "\n[!!] ANOMALOUS USAGE DETECTED : %s",
                        ctime((const time_t*)&window_distribution->start_time.tv_sec));
                printf("  RDev: %f\n  WDev: %f\n", baseline_distribution->standard_deviation, std);
                printf("  Norm: ");
                print_distribution(baseline_distribution);
                printf("  Capd: ");
                print_distribution(window_distribution);
                num_attacks++;
            }
        }
    }

    printf("Num attacks  : %d\n", num_attacks);

    // This will never be reached
    pcap_close(descr);
    free (baseline_distribution);
    free (window_distribution);
    return 0;
}

