/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      udp_scanner.c                                                   *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

/* Local modules */
#include "../headers/udp_scanner.h"
#include "../headers/scan_struc.h"

/* Standard libraries */
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

/* Network libraries */
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h> // pton()
#include <net/ethernet.h>
#include <pcap.h> // libpcap
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/if.h>           // struct ifreq
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.

/* Function handles incoming packet */
void udp_handler_ip4(u_char *handler_return, const struct pcap_pkthdr *header, const u_char *packet) {
  (void) header;
  static int p_count = 1;

  struct icmphdr *icmphdr = (struct icmphdr *)( packet + sizeof(struct ethhdr) + sizeof(struct ip));

  if (icmphdr->type == ICMP_DEST_UNREACH) {
    *handler_return = PORT_CLOSED;
  }

  p_count++;
}

/* Allocate memory for an array of unsigned chars */
uint8_t *allocate_ustrmem_udp(int len) {
  void *tmp;

  if (len <= 0) {
    fprintf(stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit(EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc(len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset(tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf(stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit(EXIT_FAILURE);
  }
}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function compute checksum */
uint16_t checksum(uint16_t *addr, int len) {
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function compute checksum for UDP protocol */
uint16_t udp4_checksum(struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen) {
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy UDP length to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function fills IPv4 protocol (UDP) */
void fill_ip4_header_udp(struct ip *iphdr, SCAN_STRUC *scan_struc, int datalen) {
  int ip_flags[4];

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr->ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr->ip_v = 4;

  // Type of service (8 bits)
  iphdr->ip_tos = 0;

  // Total length of datagram (16 bits): IP header + UDP header + datalen
  iphdr->ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  iphdr->ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr->ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  iphdr->ip_ttl = 255;

  // Transport layer protocol (8 bits): 17 for UDP
  iphdr->ip_p = IPPROTO_UDP;

  // Source IPv4 address (32 bits)
  iphdr->ip_src = scan_struc->src_ipv4_address;

  // Destination IPv4 address (32 bits)
  iphdr->ip_dst = scan_struc->dst_ipv4_address;

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr->ip_sum = 0;
  iphdr->ip_sum = checksum((uint16_t *) &iphdr, IP4_HDRLEN);
}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function fills UDP header */
void fill_udp_header_ip4(struct udphdr *udphdr, struct ip iphdr, SCAN_STRUC *scan_struc, uint8_t *data, int datalen) {
  // Source port number (16 bits): pick a number
  udphdr->source = htons(SRC_PORT);

  // Destination port number (16 bits): pick a number
  udphdr->dest = htons(scan_struc->udp_ports[scan_struc->udp_port_index]);

  // Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr->len = htons (UDP_HDRLEN + datalen);

  // UDP checksum (16 bits)
  udphdr->check = udp4_checksum(iphdr, *udphdr, data, datalen);
}

/* Function create UDP raw socket */
int create_udp_socket_ip4(int *sock_descr, SCAN_STRUC *scan_struc) {
  if ((*sock_descr = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
   return 1;
  }

  const int on = 1;
  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt(*sock_descr, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
   return 1;
  }

  struct ifreq ifr;
  // Use ioctl() to look up interface index which we will use to
  // bind socket descriptor sd to specified interface with setsockopt() since
  // none of the other arguments of sendto() specify which interface to use.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", scan_struc->src_interface);
  if (ioctl (*sock_descr, SIOCGIFINDEX, &ifr) < 0) {
    return 1;
  }

  // Bind socket to interface index.
  if (setsockopt (*sock_descr, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    return 1;
  }

  return 0;
}

/* Function terminates pcap_loop() */
void terminate_process_UDP() {
   pcap_breakloop(handle);
}

/* Function scanning UDP ports */
int udp_scanner_ip4(SCAN_STRUC *scan_struc) {
  uint8_t *packet, *data;
  struct ip iphdr;
  struct udphdr udphdr;
  struct sockaddr_in sin;

  packet = allocate_ustrmem_udp(IP_MAXPACKET);
  data = allocate_ustrmem_udp(IP_MAXPACKET);
  int datalen = 4;
  data[0] = 'T';
  data[1] = 'e';
  data[2] = 's';
  data[3] = 't';

  fill_ip4_header_udp(&iphdr, scan_struc, datalen);
  fill_udp_header_ip4(&udphdr, iphdr, scan_struc, data, datalen);

  memcpy(packet, &iphdr, IP4_HDRLEN * sizeof (uint8_t));
  memcpy((packet + IP4_HDRLEN), &udphdr, UDP_HDRLEN * sizeof (uint8_t));
  memcpy(packet + IP4_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));

  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;
  sin.sin_port = udphdr.dest;

  char errbuf[PCAP_ERRBUF_SIZE];

  bpf_u_int32 net, mask = 0;
  if (pcap_lookupnet(scan_struc->src_interface, &net, &mask, errbuf) == -1) {
    return 1;
  }

  handle = pcap_open_live(scan_struc->src_interface, BUFSIZ, 1, PCAP_READ_TIME, errbuf);
  if (handle == NULL) {
    return 1;
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    pcap_close(handle);

    return 1;
  }

  int sock_descr = 0;
  if (create_udp_socket_ip4(&sock_descr, scan_struc)) {
    return 1;
  }

  if (sendto(sock_descr, packet, IP4_HDRLEN + UDP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    return 1;
  }

  struct bpf_program fp; // Compiled filter
  char filter[50];
  char filter_address[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(scan_struc->src_ipv4_address), filter_address, INET_ADDRSTRLEN);
  sprintf(filter, "dst host %s && icmp", filter_address);

  if (mask) {
    if (pcap_compile(handle, &fp, filter, 0, mask) == -1) {
      pcap_close(handle);

      return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
      pcap_close(handle);

      return 1;
    }
  }

  signal(SIGALRM, terminate_process_UDP);
  alarm(2);

  unsigned char pcap_loop_ret = PORT_OPEN;
  pcap_loop(handle, 1, udp_handler_ip4, &pcap_loop_ret);
  if (pcap_loop_ret == PORT_CLOSED) {
    scan_struc->udp_ports_result[scan_struc->udp_port_index] = strdup("closed");
    if (scan_struc->udp_ports_result[scan_struc->udp_port_index] == NULL) {
      return 2;
    }
  }
  else {
    signal(SIGALRM, terminate_process_UDP);
    alarm(2);

    pcap_loop(handle, 1, udp_handler_ip4, &pcap_loop_ret);
    scan_struc->udp_ports_result[scan_struc->udp_port_index] = strdup("open");
    if (scan_struc->udp_ports_result[scan_struc->udp_port_index] == NULL) {
      return 2;
    }
  }

  // Close socket descriptor.
  close(sock_descr);
  free(packet);
  pcap_close(handle);

  return 0;
}

/******************************************************************************/
/*                                    IPv6                                    */
/******************************************************************************/

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function compute checksum for UDP protocol */
uint16_t udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen) {
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);
  chksumlen += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy UDP length into buf (32 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function fills IPv6 protocol (UDP) */
void fill_ip6_header_udp(struct ip6_hdr *iphdr, SCAN_STRUC *scan_struc, int datalen) {
  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits): TCP header
  iphdr->ip6_plen = htons (UDP_HDRLEN + datalen);

  // Next header (8 bits):UDP
  iphdr->ip6_nxt = IPPROTO_UDP;

  // Hop limit (8 bits): default to maximum value
  iphdr->ip6_hops = 255;

  // Source IPv6 address (128 bits)
  iphdr->ip6_src = scan_struc->src_ipv6_address;

  // Destination IPv6 address (128 bits)
  iphdr->ip6_dst = scan_struc->dst_ipv6_address;
}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function fills UDP header */
void fill_udp_header_ip6(struct udphdr *udphdr, struct ip6_hdr iphdr, SCAN_STRUC *scan_struc, uint8_t *data, int datalen) {
  // Source port number (16 bits): pick a number
  udphdr->source = htons(SRC_PORT);

  // Destination port number (16 bits): pick a number
  udphdr->dest = htons(scan_struc->udp_ports[scan_struc->udp_port_index]);

  // Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr->len = htons (UDP_HDRLEN + datalen);

  // UDP checksum (16 bits)
  udphdr->check = udp6_checksum(iphdr, *udphdr, data, datalen);
}

/* Function create UDP raw socket */
int create_udp_socket_ip6(int *sock_descr, SCAN_STRUC *scan_struc) {
  if ((*sock_descr = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
   return 1;
  }

  const int on = 1;
  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt(*sock_descr, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof (on)) < 0) {
   return 1;
  }

  struct ifreq ifr;
  // Use ioctl() to look up interface index which we will use to
  // bind socket descriptor sd to specified interface with setsockopt() since
  // none of the other arguments of sendto() specify which interface to use.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", scan_struc->src_interface);
  if (ioctl (*sock_descr, SIOCGIFINDEX, &ifr) < 0) {
    return 1;
  }

  // Bind socket to interface index.
  if (setsockopt (*sock_descr, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
    return 1;

  }
  return 0;
}

/* Function handles incoming packet */
void udp_handler_ip6(u_char *handler_return, const struct pcap_pkthdr *header, const u_char *packet) {
  (void) header;

  static int p_count = 1;

  struct icmp6_hdr *icmphdr = (struct icmp6_hdr *)( packet + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
  if (icmphdr->icmp6_type == ICMP6_DST_UNREACH) {
    *handler_return = PORT_CLOSED;
  }

  p_count++;
}

/* Function scanning UDP ports */
int udp_scanner_ip6(SCAN_STRUC *scan_struc) {
  uint8_t *packet, *data;
  struct ip6_hdr iphdr;
  struct udphdr udphdr;
  struct sockaddr_in6 sin;

  packet = allocate_ustrmem_udp(IP_MAXPACKET);
  data = allocate_ustrmem_udp(IP_MAXPACKET);
  int datalen = 4;
  data[0] = 'T';
  data[1] = 'e';
  data[2] = 's';
  data[3] = 't';

  fill_ip6_header_udp(&iphdr, scan_struc, datalen);
  fill_udp_header_ip6(&udphdr, iphdr, scan_struc, data, datalen);

  memcpy(packet, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
  memcpy((packet + IP6_HDRLEN), &udphdr, UDP_HDRLEN * sizeof (uint8_t));
  memcpy(packet + IP6_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));

  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin6_family = AF_INET6;
  sin.sin6_addr = iphdr.ip6_dst;

  char errbuf[PCAP_ERRBUF_SIZE];

  bpf_u_int32 net, mask = 0;
  if (pcap_lookupnet(scan_struc->src_interface, &net, &mask, errbuf) == -1) {
    return 1;
  }

  handle = pcap_open_live(scan_struc->src_interface, BUFSIZ, 1, PCAP_READ_TIME, errbuf);
  if (handle == NULL) {
    return 1;
  }

  if (pcap_datalink(handle) != DLT_EN10MB) {
    pcap_close(handle);

    return 1;
  }

  int sock_descr = 0;
  if (create_udp_socket_ip6(&sock_descr, scan_struc)) {
    return 1;
  }

  // Send packet.
  if (sendto(sock_descr, packet, IP6_HDRLEN + UDP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (struct  sockaddr_in6)) < 0)  {
    return 1;
  }

  struct bpf_program fp; // Compiled filter
  char filter[50];
  char filter_address[INET_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(scan_struc->src_ipv6_address), filter_address, INET_ADDRSTRLEN);
  sprintf(filter, "dst host %s && icmp6", filter_address);

  if (mask) {
    if (pcap_compile(handle, &fp, filter, 0, mask) == -1) {
      pcap_close(handle);

      return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
      pcap_close(handle);

      return 1;
    }
  }
  signal(SIGALRM, terminate_process_UDP);
  alarm(2);

  unsigned char pcap_loop_ret = PORT_OPEN;
  pcap_loop(handle, 1, udp_handler_ip6, &pcap_loop_ret);
  if (pcap_loop_ret == PORT_CLOSED) {
    scan_struc->udp_ports_result[scan_struc->udp_port_index] = strdup("closed");
    if (scan_struc->udp_ports_result[scan_struc->udp_port_index] == NULL) {
      return 2;
    }
  }
  else {
    signal(SIGALRM, terminate_process_UDP);
    alarm(2);

    pcap_loop(handle, 1, udp_handler_ip6, &pcap_loop_ret);
    scan_struc->udp_ports_result[scan_struc->udp_port_index] = strdup("open");
    if (scan_struc->udp_ports_result[scan_struc->udp_port_index] == NULL) {
      return 2;
    }
  }

  // Close socket descriptor.
  close(sock_descr);
  free(packet);
  pcap_close(handle);

  return 0;
}
