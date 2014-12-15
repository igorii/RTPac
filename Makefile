all: main.cpp entropy.o cli_opts.o distributions.o
	g++ -o rtpac main.cpp entropy.o cli_opts.o distributions.o gnuplot_i.o -lpcap -Ignuplot_i/src

entropy.o: entropy.cpp entropy.h
	g++ -c entropy.cpp

cli_opts.o: cli_opts.cpp cli_opts.h
	g++ -c cli_opts.cpp

distributions.o: distributions.cpp distributions.h
	g++ -c distributions.cpp
