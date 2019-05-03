################################################################################
# Project:   2BIT IPK, Project 2                                               #
#            Faculty of Information Technolgy                                  #
#            Brno University of Technology                                     #
# File:      Makefile                                                          #
# Date:      21.04.2019                                                        #
# Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                         #
################################################################################

CC=gcc
CFLAGS=-pedantic -Wall -Wextra
OF= scan_struc.o help.o args_parser.o get_ip.o tcp_scanner.o udp_scanner.o
SCANNER= ipk-scan

scan: code/scan.c $(OF)
	$(CC) $(CFLAGS) code/scan.c $(OF) -o $(SCANNER) -lpcap
	rm -f $(OF)

scan_struc.o: code/scan_struc.c headers/scan_struc.h
	$(CC) $(CFLAGS) -c code/scan_struc.c -o scan_struc.o

args_parser.o: code/args_parser.c headers/args_parser.h
	$(CC) $(CFLAGS) -c code/args_parser.c -o args_parser.o

help.o: code/help.c headers/help.h
	$(CC) $(CFLAGS) -c code/help.c -o help.o

get_ip.o: code/get_ip.c headers/get_ip.h
	$(CC) $(CFLAGS) -c code/get_ip.c -o get_ip.o

tcp_scanner.o: code/tcp_scanner.c headers/tcp_scanner.h
	$(CC) $(CFLAGS) -c code/tcp_scanner.c -o tcp_scanner.o

udp_scanner.o: code/udp_scanner.c headers/udp_scanner.h
	$(CC) $(CFLAGS) -c code/udp_scanner.c -o udp_scanner.o

clear-of:
	rm -f $(OF)

valgrind:
	valgrind ./$(SCANNER) -pt 21,22,23 -pu 53 localhost

run:
	sudo ./$(SCANNER) -pt 80,103 -pu 80,59395 localhost

tar:
	tar -cf xkruty00.tar args_parser.c args_parser.h \
	                     error_codes.h \
											 get_ip.c get_ip.h \
											 help.c help.h \
											 Makefile \
											 manual.pdf \
											 README \
											 scan.c \
											 scan_struc.c scan_struc.h \
											 tcp_scanner.c tcp_scanner.h \
											 udp_scanner.c udp_scanner.h
