#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <set>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <iostream>

#include "gnuplot_i/src/gnuplot_i.h"

#include "defs.h"
#include "entropy.h"
#include "cli_opts.h"
#include "distributions.h"

#define SIZE_ETHERNET 14

pcap_t*       descr;   // PCAP id, global for self access within pcap_loop to break out
unsigned char verbose; // Global verbosity level

// @see "A Network Anomaly Detection Method
//       Based on Relative Entropy Theory"
//       -- Ya-ling Zhang, Zhao-gou Han, Jiao-xia Ren

typedef struct s_callback_data {
    packet_distribution window;
    packet_distribution baseline;
} callback_data;

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
    int payload_size;

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        return;
    }

    // Update distributions
    distrib->count++;
    distrib->dst_port            [ ntohs(tcp->th_dport)                     ]++;
    distrib->dst_port_class      [ get_dst_port_class(ntohs(tcp->th_dport)) ]++;
    distrib->pkt_len_class       [ get_packet_length_class(pkthdr)          ]++;
    distrib->protocol_flag_class [ get_protocol_flag(P_TCP, tcp)            ]++;

    // Get the payload size
    payload_size = ntohs(ip->ip_len) - (size_ip + size_tcp);

    // Print if in verbose mode
    if (verbose) {

        // Print timestamp
        printf("\n%s", ctime((const time_t*)&pkthdr->ts.tv_sec));

        // Ethernet
        printf("[Ether] %s -> ", ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
        printf("%s\n",           ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));

        // IP
        printf("[IP   ] ");
        printf("%s:%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
        printf("%s:%d\n",   inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

        // Print IP and TCP header info
        printf("[TCP  ] ");

        // Print TCP flags (helps to follow stream)
#define CHECK_BIT(var,pos) ((var) & (pos))
        printf("%c%c%c%c%c%c  ",
                (CHECK_BIT(tcp->th_flags, TH_URG) ? 'U' : '-'),
                (CHECK_BIT(tcp->th_flags, TH_SYN) ? 'S' : '-'),
                (CHECK_BIT(tcp->th_flags, TH_ACK) ? 'A' : '-'),
                (CHECK_BIT(tcp->th_flags, TH_FIN) ? 'F' : '-'));
                (CHECK_BIT(tcp->th_flags, TH_PUSH)? 'P' : '-'),
                (CHECK_BIT(tcp->th_flags, TH_RST) ? 'R' : '-'),

        // Print syn/ack numbers
        printf("Seq|%u   Ack|%u \n",
                ntohl(tcp->th_seq), ntohl(tcp->th_ack));

        // Attributes
        printf("[HLen ]  %d\n", size_ip);
        printf("[Data ]  %d\n", payload_size);

        // Print statistical information
        printf("   Dst Class Entropy        : %f\n",
                entropy_of_distribution(distrib->count,
                    distrib->dst_port_class, CDSTN));

        printf("   Pkt Length Entropy       : %f\n",
                entropy_of_distribution(distrib->count,
                    distrib->pkt_len_class, LENN));

        printf("   Protocol Flag  Entropy   : %f\n",
                entropy_of_distribution(distrib->count,
                    distrib->protocol_flag_class, PFLN));

        printf("   Destination Port Entropy : %f\n\n",
                entropy_of_distribution(distrib->count,
                    distrib->dst_port, DSTN));

        // Print the payload data
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        if (payload_size > 0) {
            print_hex (payload);
        }

        // Print an end break
        printf("\n");
        for (int i = 0; i < 80; ++i) printf("-");
        printf("\n");
    }
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

    if (verbose) {

        // Print timestamp
        printf("\n%s", ctime((const time_t*)&pkthdr->ts.tv_sec));

        // Ethernet
        printf("[Ether] %s -> ",  ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
        printf("%s\n",            ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));

        // IP
        printf("[IP   ] ");
        printf("%s:%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->sport));
        printf("%s:%d\n",   inet_ntoa(ip->ip_dst), ntohs(udp->dport));

        // Print UDP info
        printf("[UDP   ] \n");

        // Attributes
        printf("[HLen ]  %d\n", size_ip);
    }
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
    //
    // Ethernet header
    ethernet = (struct sniff_ethernet*)(packet);

    // IP header
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20 /*bytes*/ ) {
        return; // Invalid IP header length
    }

    // Dispatch to the correct protocol handler
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            process_tcp_packet(distrib, pkthdr, packet, ethernet, ip, size_ip);
            break;
        case IPPROTO_UDP:
            if (verbose) {
                process_tcp_packet(distrib, pkthdr, packet, ethernet, ip, size_ip);
            }
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

// Add a point to a gnu graph and scroll left
int add_point(gnuplot_ctrl *plotid, double *points, int npoints, double point)
{
    int i, j;
    for (i = 0; i < npoints - 1; ++i) {
        points[i] = points[i + 1];
    }

    points[npoints - 1] = point;

    // Draw the graph
    gnuplot_resetplot(plotid);
    gnuplot_plot_x(plotid, points, npoints, "Network entropy") ;
}

// Return the frequency sum of all frequencies in a distribution
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

// Ensure the probability sums are equal to 1
unsigned char sanity_check_distribution (packet_distribution *distrib)
{
    // All sums should be 1
    return (0.001 > 1 - sanity_check_probabilities (PFLN,
                distrib->count, distrib->protocol_flag_class) &&
            0.001 > 1 - sanity_check_probabilities (LENN,
                distrib->count, distrib->pkt_len_class));
}

//Print the entropies
void relative_entropy_of_distributions (
        packet_distribution *distrib1,
        packet_distribution *distrib2)
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

// Capture and model the regular network traffic
void capture_regular_deviation(
        gnuplot_ctrl *plotid,
        double *points,
        int npoints,
        packet_distribution *baseline,
        cli_opts *opts)
{
    int i, max_window_num;
    unsigned char distribution_correct;
    packet_distribution window;

    if (opts->live) {
        max_window_num = opts->max_window_num;
    } else {
        max_window_num = floor(baseline->count / opts->max_window_count);
    }

    double window_history[max_window_num];

    for (i = 0; i < max_window_num; ++i) {
        bzero(&window, sizeof (packet_distribution));
        window.max_count = opts->max_window_count;
        fprintf (stderr, "Beginning window %d capture of baseline... ", i);
        fflush(stderr);
        pcap_loop(descr, -1, process_packet, (u_char *)&window);

        // Sanity check, ensure all probability vectors sum to 1
        //        Kullback-Leibler divergence is only defined at this point
        distribution_correct = sanity_check_distribution(&window);
        print_distribution_to_stderr(&window);
        if (!distribution_correct) {
            printf("Window distribution is not correct\n");
            exit(1);
        } else {
            // The distribution is correct in this case, so proceed...
            // Calculate the relative entropy of the two distributions
            window_history[i] = normalized_relative_network_entropy(&window, baseline, opts);
        }
    }

    // Store the standard deviation in the given distribution
    baseline->mean               = mean(window_history,    max_window_num);
    baseline->standard_deviation = std_dev(window_history, max_window_num);
}

// Open libpcap live
pcap_t *open_live(pcap_direction_t dir) {
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

    pcap_setdirection(descr, dir);
    return descr;
}

// Open libpcap on a log file
pcap_t *open_offline(const char *file, pcap_direction_t dir) {
    char errbuf[PCAP_ERRBUF_SIZE];

    descr = pcap_open_offline(file, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    pcap_setdirection(descr, dir);
    return descr;
}

// Open libpcap online or offline specified in the options
pcap_t *pcap_open (cli_opts *opts, unsigned char isTraining)
{
    pcap_direction_t dir;
    switch (opts->mode) {
        case 'a': dir = PCAP_D_INOUT; break;
        case 'i': dir = PCAP_D_IN;    break;
        case 'o': dir = PCAP_D_OUT;   break;
        default:  dir = PCAP_D_INOUT; break;
    }

    if (opts->live) {
        return open_live(dir);
    } else if (isTraining) {
        return open_offline(opts->training_file, dir);
    } else {
        return open_offline(opts->attack_file, dir);
    }
}

packet_distribution *new_distribution() {
    packet_distribution *distribution;
    distribution = (packet_distribution *) malloc ( sizeof (packet_distribution) );
    bzero(distribution, sizeof (packet_distribution));
    return distribution;
}

int populate_baseline (
        packet_distribution *baseline,
        cli_opts *opts,
        double *points,
        int npoints,
        gnuplot_ctrl *plotid)
{
    unsigned char distribution_correct;

    // Open the interface
    descr = pcap_open(opts, 1);

    // Begin capturing packets for baseline behaviour
    fprintf(stderr, "Beginning initial baseline training...\n\n");
    baseline->max_count = opts->max_baseline_count;
    pcap_loop(descr, -1, process_packet, (u_char *)baseline);
    distribution_correct = sanity_check_distribution(baseline);
    if (!distribution_correct) {
        fprintf(stderr, "Baseline distribution is not correct\n");
        exit(1);
    }

    // Close the baseline interface
    pcap_close(descr);

    // Open the window interface
    descr = pcap_open(opts, 1);

    // Capture the regular deviation of traffic
    capture_regular_deviation(plotid, points, npoints, baseline, opts);

    // Print finished status
    fprintf (stderr, "\nFinished capturing baseline behaviour ");
    print_distribution_to_stderr(baseline);
    fprintf(stderr, "Regular deviation: %f\n\n", baseline->standard_deviation);
    pcap_close(descr);
}

double c_abs (double x)
{
    if (x < 0) return 0 - x;
    else       return x;
}

void monitor_traffic (
        cli_opts *opts,
        packet_distribution *baseline,
        double *points,
        int npoints,
        gnuplot_ctrl *plotid)
{
    double nrne;
    double std;
    unsigned char distribution_correct;
    int num_attacks = 0;
    int num_windows = 0;
    packet_distribution *window;
    descr = pcap_open(opts, 0);
    window = new_distribution();

    printf("Watching for entropy difference %f...\n", opts->cutoff);

    // Begin capturing window distributions and comparing every `window_size_in_pkts` many captures
    for (;;) {

        // Reset the window distribution
        bzero(window, sizeof (packet_distribution));
        window->max_count = opts->max_window_count;
        pcap_loop(descr, -1, process_packet, (u_char *)window);

        // If we have finished reading the file, break out of the loop
        if (window->count < window->max_count) {
            break;
        }

        num_windows++;

        // Sanity check, ensure all probability vectors sum to 1
        //        Kullback-Leibler divergence is only defined at this point
        distribution_correct = sanity_check_distribution(window);
        if (!distribution_correct)
        {
            fprintf(stderr, "Window distribution is not correct, ignoring window\n");
            print_distribution_to_stderr(window);
        }
        else
        {
            // The distribution is correct in this case, so proceed...
            // Calculate the relative entropy of the two distributions
            nrne = normalized_relative_network_entropy(window, baseline, opts);
            std  = square_difference(nrne, baseline->mean);
            //std = c_abs(nrne - baseline->mean) / baseline->standard_deviation;

            // Add the points to the real-time chart
            if (opts->graph) {
                add_point(plotid, points, npoints, std);
            }

            // Check for anomaly
            if (std > opts->cutoff) {
                fprintf(stderr, "\n[!!] ANOMALOUS USAGE DETECTED : %s",
                        ctime((const time_t*)&window->start_time.tv_sec));
                fprintf(stderr, "  RDev: %f\n  WDev: %f\n", baseline->standard_deviation, std);
                fprintf(stderr, "  Norm: ");
                print_distribution_to_stderr(baseline);
                fprintf(stderr, "  Capd: ");
                print_distribution_to_stderr(window);
                num_attacks++;
            }
            }
        }

        // Print the number of attacks observed in the attack file
        printf("Num attacks : %d\n", num_attacks);
        printf("Num windows : %d\n", num_windows);
        fprintf(stderr, "\nBASELINE START : %s",
                ctime((const time_t*)&baseline->start_time.tv_sec));

        // This will only be reached if not running live
        pcap_close(descr);
        free (window);
    }

    int main(int argc, char **argv)
    {
        packet_distribution *baseline_distribution;
        cli_opts opts;
        gnuplot_ctrl *gnuplot_id;

#define NPOINTS 100
        double points[NPOINTS];
        bzero(points, sizeof(points));

        parse_args(argc, argv, &opts);
        verbose = opts.verbose;

        // Initialize the real-time chart as line chart
        gnuplot_id = gnuplot_init();
        gnuplot_setstyle(gnuplot_id, "lines");

        // Initialize the running distribution
        baseline_distribution = new_distribution();

        // Populate the baseline distribution
        populate_baseline(baseline_distribution, &opts, points, NPOINTS, gnuplot_id);

        // Monitor the traffic for anomalies
        monitor_traffic(&opts, baseline_distribution, points, NPOINTS, gnuplot_id);

        std::cin.get();

        // Cleanup memory and resources
        free (baseline_distribution);
        gnuplot_close(gnuplot_id) ;
        return 0;
    }

