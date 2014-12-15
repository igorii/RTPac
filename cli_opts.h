#ifndef CLI_OPTS_H
#define CLI_OPTS_H

typedef struct opts {
    unsigned char live;
    unsigned char verbose;
    unsigned char graph;

#define BUFFERSIZ 256
    char training_file[BUFFERSIZ];
    char attack_file[BUFFERSIZ];
    int max_baseline_count;
    int max_window_count;
    int max_window_num;

    unsigned char use_dst_port_class;
    unsigned char use_dst_port;
    unsigned char use_pkt_len;
    unsigned char use_protocol_flag;

    char mode;

    opts(): live(1),
            verbose(0),
            graph(0),
            mode('a'),
            max_baseline_count(1000),
            max_window_count(1000),
            max_window_num(10),
            use_dst_port_class(0),
            use_dst_port(0),
            use_protocol_flag(0),
            use_pkt_len(0) {}
} cli_opts;

void parse_args(int, char **, cli_opts *);

#endif
