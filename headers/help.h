/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      help.h                                                          *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/
#ifndef _HELP_H_
#define _HELP_H_

/* Constants */
#define HELP_MSG "Usage of \"ipk-scan\":\n\n" \
                  "$ ./ipk-scan {-i <interface>} -pu <port-ranges> -pt <por-ranges> [<domain-name> | <IP-address>]\n\n" \
                  "where:\n" \
                  "\t-pu <port-ranges>\t\tScanned UDP ports\n" \
                  "\t-pt <port-ranges>\t\tScanned TCP ports\n" \
                  "\t[<domain-name> | <IP-address>]\tIdentification of scanning machine\n" \
                  "\t-i <interface>\t\t\tInterface identification\n\n"

/**
 * Function prints help message on stdout
 */
void print_help();

#endif /* _HELP_H_ */
