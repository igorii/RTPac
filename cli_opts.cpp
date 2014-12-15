#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli_opts.h"

void parse_args(int argc, char **argv, cli_opts *opts) {
    int m, n, l, x, ch;
    char s[BUFFERSIZ];

    for (n = 1; n < argc; n++) {
        switch ((int)argv[n][0]) {
            case '-':
            case '/': x = 0;
                      l = strlen(argv[n]);
                      for (m = 1; m < l; ++m) {
                          ch = (int)argv[n][m];
                          switch (ch) {
                              case 'u': if (m + 1 >= l) {
                                            puts( "Illegal syntax -- no argument" );
                                            exit(1);
                                        } else {
                                            strcpy(s, &argv[n][m+1]);
                                            if (0 == strcmp(s, "p")) {
                                                opts->use_dst_port = 1;
                                            } else if (0 == strcmp(s, "pc")) {
                                                opts->use_dst_port_class = 1;
                                            } else if (0 == strcmp(s, "l")) {
                                                opts->use_pkt_len = 1;
                                            } else if (0 == strcmp(s, "pf")) {
                                                opts->use_protocol_flag = 1;
                                            }
                                        }
                                        x = 1;
                                        break;
                              case 'm': if (m + 1 >= l) {
                                            puts( "Illegal syntax -- no argument" );
                                            exit(1);
                                        } else {
                                            strcpy(s, &argv[n][m+1]);
                                            if (0 == strcmp(s, "a")) {
                                                opts->mode = 'a';
                                            } else if (0 == strcmp(s, "i")) {
                                                opts->mode = 'i';
                                            } else if (0 == strcmp(s, "o")) {
                                                opts->mode = 'o';
                                            }
                                        }
                                        x = 1;
                                        break;
                              case 'l':
                                        if (m + 1 >= l) {
                                            puts( "Illegal syntax -- no argument" );
                                            exit(1);
                                        } else {
                                            strcpy(s, &argv[n][m+1]);
                                            opts->live = 0 == strcmp(s, "y");
                                        }
                                        x = 1;
                                        break;
                              case 'v':
                                        opts->verbose = 1;
                                        x = 1;
                                        break;
                              case 'g':
                                        opts->graph = 1;
                                        x = 1;
                                        break;
                              case 'b': if (m + 1 >= l) {
                                            puts( "Illegal syntax -- no argument" );
                                            exit(1);
                                        } else {
                                            strcpy(s, &argv[n][m+1]);
                                            opts->max_baseline_count = atoi(s);
                                        }
                                        x = 1;
                                        break;
                              case 'w': if (m + 1 >= l) {
                                            puts( "Illegal syntax -- no argument" );
                                            exit(1);
                                        } else {
                                            strcpy(s, &argv[n][m+1]);
                                            opts->max_window_count = atoi(s);
                                        }
                                        x = 1;
                                        break;
                              case 'n': if (m + 1 >= l) {
                                            puts( "Illegal syntax -- no argument" );
                                            exit(1);
                                        } else {
                                            strcpy(s, &argv[n][m+1]);
                                            opts->max_window_num = atoi(s);
                                        }
                                        x = 1;
                                        break;
                              case 't': if (m + 1 >= l) {
                                            puts( "Illegal syntax -- no argument" );
                                            exit(1);
                                        } else {
                                            strcpy(s, &argv[n][m+1]);
                                            strcpy(opts->training_file, s);
                                        }
                                        x = 1;
                                        break;
                              case 'a': if (m + 1 >= l) {
                                            puts( "Illegal syntax -- no argument" );
                                            exit(1);
                                        } else {
                                            strcpy(s, &argv[n][m+1]);
                                            strcpy(opts->attack_file, s);
                                        }
                                        x = 1;
                                        break;
                              default:  printf( "Illegal option code = %c\n", ch );
                                        x = 1;
                                        exit(1);
                                        break;
                          }
                          if(x == 1) {
                              break;
                          }
                      }
                      break;
            default:  printf( "Text = %s\n", argv[n] );
                      break;
        }
    }
}
