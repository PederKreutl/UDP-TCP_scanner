/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      scan_struc.c                                                    *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

/* Local modules */
#include "../headers/scan_struc.h"

/* Standard libraries */
#include <string.h>
#include <stdlib.h>

/* Network libraries */
#include <netinet/in.h>

/* Function initializes main scanning structure */
int init_scan_struc(SCAN_STRUC *scan_struc) {
  /* Ports */
  scan_struc->tcp_ports = NULL;
  scan_struc->udp_ports = NULL;
  scan_struc->tcp_ports_result = NULL;
  scan_struc->udp_ports_result = NULL;
  scan_struc->tcp_ports_count = 0;
  scan_struc->udp_ports_count = 0;
  scan_struc->tcp_port_index = 0;
  scan_struc->udp_port_index = 0;

  /* Source */
  scan_struc->src_interface = NULL;
  scan_struc->src_ipv4_address.s_addr = INADDR_ANY;
  scan_struc->src_ipv6_address = in6addr_any;

  /* Destination */
  scan_struc->machine_id = NULL;
  scan_struc->domain_name_flag = false;
  scan_struc->dst_ip_type = 0;
  scan_struc->dst_ipv4_address.s_addr = INADDR_ANY;
  scan_struc->dst_ipv6_address = in6addr_any;
  scan_struc->dst_ip_address = NULL;

  return 0;
}

/* Function deallocates main scanning structure */
void free_scan_struc(SCAN_STRUC *scan_struc) {
    free(scan_struc->tcp_ports_result);
    free(scan_struc->udp_ports_result);
    free(scan_struc->machine_id);
    free(scan_struc->tcp_ports);
    free(scan_struc->udp_ports);
    free(scan_struc->src_interface);
}
