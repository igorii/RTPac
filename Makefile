all: main.cpp entropy.o cli_opts.o
	g++ -o rtpac main.cpp entropy.o cli_opts.o -lpcap

entropy.o: entropy.cpp entropy.h
	g++ -c entropy.cpp

cli_opts.o: cli_opts.cpp cli_opts.h
	g++ -c cli_opts.cpp
