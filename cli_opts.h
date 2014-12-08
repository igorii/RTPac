#ifndef CLI_OPTS_H
#define CLI_OPTS_H

typedef struct opts {
    unsigned char live;
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
} cli_opts;

void parse_args(int, char **, cli_opts *);

#endif
