all: main.cpp entropy.o
	g++ -o rtpac main.cpp entropy.o -lpcap

entropy.o: entropy.cpp entropy.h
	g++ -c entropy.cpp
