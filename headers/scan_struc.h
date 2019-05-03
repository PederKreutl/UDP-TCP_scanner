/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      scan_struc.h                                                    *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/
#ifndef _SCAN_STRUC_H_
#define _SCAN_STRUC_H_

/* Standard libraries */
#include <stdbool.h>

/* Network libraries */
#include <netinet/in.h> // struct sockaddr_in/sockaddr_in6
#include <pcap.h>

/* Constants */
#define SRC_PORT 5678

#define DOMAIN_NAME 0
#define IPV4_TYPE 4
#define IPV6_TYPE 6

#define PORT_CLOSED 0
#define PORT_OPEN 1
#define PORT_FILTERED 2

#define PCAP_READ_TIME 1000

#define IP4_HDRLEN 20
#define IP6_HDRLEN 40
#define TCP_HDRLEN 20
#define UDP_HDRLEN 8

pcap_t *handle;

/* Main scanning structure */
typedef struct scan_struc {
  /* Ports */
  int *tcp_ports;
  int *udp_ports;
  char **tcp_ports_result;
  char **udp_ports_result;
  int tcp_ports_count;
  int udp_ports_count;
  int tcp_port_index;
  int udp_port_index;

  /* Source */
  char *src_interface;
  struct in_addr src_ipv4_address;
  struct in6_addr src_ipv6_address;

  /* Destination */
  char *machine_id;
  bool domain_name_flag;
  int dst_ip_type;
  struct in_addr dst_ipv4_address;
  struct in6_addr dst_ipv6_address;
  char *dst_ip_address;
} SCAN_STRUC;

/**
 * Function initializes main scanning structure
 *
 * @param[in] scan_struc Main scanning structure
 * @return Function result
 */
int init_scan_struc(SCAN_STRUC *scan_struc);

/**
 * Function deallocates main scanning structure
 *
 * @param[in] scan_struc Main scanning structure
 * @return Function result
 */
void free_scan_struc(SCAN_STRUC *scan_struc);

#endif /* _SCAN_STRUC_H_ */
