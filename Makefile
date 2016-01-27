# Makefile for test C programs

CC	= g++

OBJ	= main.o  util.o packet.o twowayFlow.o loadbar.o pcaptopkt.o pcapReader.o pkttoflowwithpkt.o flowHash.o veri.o captopcap.o sequenceExtracter.o sequence.o timeChecker.o uniqueCount.o 

HEADER	= include.h util.h 
		

LFLAGS  =       -O -lpcap -I/usr/local/include -lpthread
CFLAGS  =       -O -I/usr/local/include -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE

all : t 


t : $(OBJ) 
	$(CC)  -o SnorGen  $(OBJ) $(LFLAGS)
	

%.o: %.cc $(HEADER)
	$(CC) $(CFLAGS) -c  $<

	
clean :
	rm -rf *.o core SnorGen
