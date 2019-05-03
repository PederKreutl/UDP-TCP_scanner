/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      scan.c                                                          *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

/* Local modules */
#include "../headers/help.h"
#include "../headers/args_parser.h"
#include "../headers/tcp_scanner.h"
#include "../headers/udp_scanner.h"
#include "../headers/scan_struc.h"
#include "../headers/get_ip.h"
#include "../headers/error_codes.h"

/* Standard libraries */
#include <stdio.h>

/* Function prints program output on stdout */
void print_output(SCAN_STRUC scan_struc) {
  if (scan_struc.domain_name_flag) {
    printf("Interesting ports on %s (%s)\n", scan_struc.machine_id, scan_struc.dst_ip_address);
  }
  else {
    printf("Interesting ports on %s\n", scan_struc.dst_ip_address);
  }

  printf("PORT \t\tSTATE\n");

  for (int i = 0; i < scan_struc.tcp_ports_count; i++) {
    if (scan_struc.tcp_ports[i] > 99) { // For beauty allignment
      printf("%d/tcp \t%s\n", scan_struc.tcp_ports[i], scan_struc.tcp_ports_result[i]);
    }
    else {
      printf("%d/tcp \t\t%s\n", scan_struc.tcp_ports[i], scan_struc.tcp_ports_result[i]);
    }
  }
  for (int i = 0; i < scan_struc.udp_ports_count; i++) {
    if (scan_struc.udp_ports[i] > 99) {
      printf("%d/udp \t%s\n", scan_struc.udp_ports[i], scan_struc.udp_ports_result[i]);
    }
    else {
      printf("%d/udp \t\t%s\n", scan_struc.udp_ports[i], scan_struc.udp_ports_result[i]);
    }
  }
}

/* Main function of program */
int main(int argc, char *argv[]) {
  SCAN_STRUC scan_struc;

  /* Sources allocation */
  if (init_scan_struc(&scan_struc)) {
    fprintf(stderr, "INTERNAL ERRROR: init_scan_struc()\n");
    return INTERNAL_ERROR;
  }

  /* Parsing arguments */
  int parse_args_ret = parse_args(argc, argv, &scan_struc);
  if (parse_args_ret == ERROR) {
    fprintf(stderr, "ERROR: Wrong program arguments\n");
    free_scan_struc(&scan_struc);
    return ERROR;
  }
  else if (parse_args_ret == INTERNAL_ERROR) {
    fprintf(stderr, "INTERNAL ERROR: parse_args()\n");
    free_scan_struc(&scan_struc);
    return INTERNAL_ERROR;
  }

  /* Getting destination IP */
  int get_dst_ip_ret = get_dst_ip(&scan_struc);
  if (get_dst_ip_ret == ERROR) {
    fprintf(stderr, "ERROR: Cannot get destination ip\n");
    free_scan_struc(&scan_struc);
    return ERROR;
  }
  else if (get_dst_ip_ret == INTERNAL_ERROR) {
    fprintf(stderr, "INTERNAL ERROR: get_dst_ip_ret()\n");
    free_scan_struc(&scan_struc);
    return INTERNAL_ERROR;
  }

  /* Getting source IP */
  int get_src_ip_ret = get_src_ip(&scan_struc);
  if (get_src_ip_ret == ERROR) {
    fprintf(stderr, "ERROR: Cannot get source ip\n");
    free_scan_struc(&scan_struc);
    return ERROR;
  }
  else if (get_src_ip_ret == INTERNAL_ERROR) {
    fprintf(stderr, "INTERNAL ERROR: get_src_ip()\n");
    free_scan_struc(&scan_struc);
    return INTERNAL_ERROR;
  }

  /* IPv4 */
  if (scan_struc.dst_ip_type == IPV4_TYPE) {
    /* TCP scanning */
    for (int i = 0; i < scan_struc.tcp_ports_count; i++) {
      int tcp_scanner_ret = tcp_scanner_ip4(&scan_struc);
      if (tcp_scanner_ret == ERROR) {
        fprintf(stderr, "ERROR: Problem with scannning TCP ports\n");
        free_scan_struc(&scan_struc);
        return ERROR;
      }
      else if (tcp_scanner_ret == INTERNAL_ERROR) {
        fprintf(stderr, "INTERNAL ERROR: tcp_scanner_ip4()\n");
        free_scan_struc(&scan_struc);
        return INTERNAL_ERROR;
      }
      (scan_struc.tcp_port_index)++;
    }

    /* UDP scanning */
    for (int i = 0; i < scan_struc.udp_ports_count; i++) {
      int udp_scanner_ret = udp_scanner_ip4(&scan_struc);
      if (udp_scanner_ret == ERROR) {
        fprintf(stderr, "ERROR: Problem with scannning UDP ports\n");
        free_scan_struc(&scan_struc);
        return ERROR;
      }
      else if (udp_scanner_ret == INTERNAL_ERROR) {
        fprintf(stderr, "INTERNAL ERROR: udp_scanner_ip4()\n");
        free_scan_struc(&scan_struc);
        return INTERNAL_ERROR;
      }
      (scan_struc.udp_port_index)++;
    }
  }
  /* IPv6 */
  else {
    /* TCP scanning */
    for (int i = 0; i < scan_struc.tcp_ports_count; i++) {
      int tcp_scanner_ret = tcp_scanner_ip6(&scan_struc);
      if (tcp_scanner_ret == ERROR) {
        fprintf(stderr, "ERROR: Problem with scannning TCP ports\n");
        free_scan_struc(&scan_struc);
        return ERROR;
      }
      else if (tcp_scanner_ret == INTERNAL_ERROR) {
        fprintf(stderr, "INTERNAL ERROR: tcp_scanner_ip6()\n");
        free_scan_struc(&scan_struc);
        return INTERNAL_ERROR;
      }
      (scan_struc.tcp_port_index)++;
    }

    /* UDP scanning */
    for (int i = 0; i < scan_struc.udp_ports_count; i++) {
      int udp_scanner_ret = udp_scanner_ip6(&scan_struc);
      if (udp_scanner_ret == ERROR) {
        fprintf(stderr, "ERROR: Problem with scannning UDP ports\n");
        free_scan_struc(&scan_struc);
        return ERROR;
      }
      else if (udp_scanner_ret == INTERNAL_ERROR) {
        fprintf(stderr, "INTERNAL ERROR: udp_scanner_ip6()\n");
        free_scan_struc(&scan_struc);
        return INTERNAL_ERROR;
      }
      (scan_struc.udp_port_index)++;
    }
  }

  /* Printing output */
  print_output(scan_struc);

  /* Sources deallocation */
  free_scan_struc(&scan_struc); // Function from "scan_struc.h"

  return 0;
}
