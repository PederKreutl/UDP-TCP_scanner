/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      tcp_scanner.c                                                   *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

/* Local modules */
#include "../headers/tcp_scanner.h"
#include "../headers/scan_struc.h"

/* Standard libraries */
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

/* Network libraries */
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h> // pton()
#include <net/ethernet.h>
#include <pcap.h> // libpcap
#include <net/if.h> // struct ifreq

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function compute checksum */
uint16_t checksum1(uint16_t *addr, int len) {
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
/* Function compute checksum for TCP protocol */
uint16_t tcp4_checksum(struct ip iphdr, struct tcphdr tcphdr) {
  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  // ptr points to beginning of buffer buf
  ptr = &buf[0];

  // Copy source IP address into buf (32 bits)
  memcpy(ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy(ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy(ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy TCP length to buf (16 bits)
  svalue = htons(sizeof (tcphdr));
  memcpy(ptr, &svalue, sizeof (svalue));
  ptr += sizeof (svalue);
  chksumlen += sizeof (svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy(ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy(ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy(ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy(ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy(ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy(ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy(ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy(ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  return checksum1((uint16_t *) buf, chksumlen);
}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function fills IPv4 protocol (TCP) */
void fill_ip4_header_tcp(struct ip *iphdr, SCAN_STRUC *scan_struc) {
    int ip_flags[4];

    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr->ip_hl = IP4_HDRLEN / sizeof (uint32_t);

    // Internet Protocol version (4 bits): IPv4
    iphdr->ip_v = 4;

    // Type of service (8 bits)
    iphdr->ip_tos = 0;

    // Total length of datagram (16 bits): IP header + TCP header
    iphdr->ip_len = htons(IP4_HDRLEN + TCP_HDRLEN);

    // ID sequence number (16 bits): unused, since single datagram
    iphdr->ip_id = htons(0);

    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

    // Zero (1 bit)
    ip_flags[0] = 0;

    // Do not fragment flag (1 bit)
    ip_flags[1] = 0;

    // More fragments following flag (1 bit)
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr->ip_off = htons((ip_flags[0] << 15)
                          + (ip_flags[1] << 14)
                          + (ip_flags[2] << 13)
                          +  ip_flags[3]);

    // Time-to-Live (8 bits): default to maximum value
    iphdr->ip_ttl = 255;

    // Transport layer protocol (8 bits): 6 for TCP
    iphdr->ip_p = IPPROTO_TCP;

    // Source IPv4 address (32 bits)

    iphdr->ip_src = scan_struc->src_ipv4_address;

    // Destination IPv4 address (32 bits)
    iphdr->ip_dst = scan_struc->dst_ipv4_address;

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr->ip_sum = 0;
    iphdr->ip_sum = checksum1((uint16_t *) &iphdr, IP4_HDRLEN);
}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function fills TCP header */
void fill_tcp_header_ip4(struct tcphdr *tcphdr, struct ip iphdr, SCAN_STRUC *scan_struc) {
    int i, tcp_flags[8];

    // Source port number (16 bits)
    tcphdr->th_sport = htons(SRC_PORT);

    // Destination port number (16 bits)
    tcphdr->th_dport = htons(scan_struc->tcp_ports[scan_struc->tcp_port_index]);

    // Sequence number (32 bits)
    tcphdr->th_seq = htonl(0);

    // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
    tcphdr->th_ack = htonl(0);

    // Reserved (4 bits): should be 0
    tcphdr->th_x2 = 0;

    // Data offset (4 bits): size of TCP header in 32-bit words
    tcphdr->th_off = TCP_HDRLEN / 4;

    // Flags (8 bits)

    // FIN flag (1 bit)
    tcp_flags[0] = 0;

    // SYN flag (1 bit): set to 1
    tcp_flags[1] = 1;

    // RST flag (1 bit)
    tcp_flags[2] = 0;

    // PSH flag (1 bit)
    tcp_flags[3] = 0;

    // ACK flag (1 bit)
    tcp_flags[4] = 0;

    // URG flag (1 bit)
    tcp_flags[5] = 0;

    // ECE flag (1 bit)
    tcp_flags[6] = 0;

    // CWR flag (1 bit)
    tcp_flags[7] = 0;

    tcphdr->th_flags = 0;
    for (i=0; i<8; i++) {
        tcphdr->th_flags += (tcp_flags[i] << i);
    }

    // Window size (16 bits)
    tcphdr->th_win = htons(65535);

    // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
    tcphdr->th_urp = htons(0);

    // TCP checksum (16 bits)
    tcphdr->th_sum = tcp4_checksum(iphdr, *tcphdr);
}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Allocate memory for an array of unsigned chars */
uint8_t *allocate_ustrmem_tcp(int len) {
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

/* Function creates TCP raw socket */
int create_ip4_tcp_socket(int *sock_descr) {
  /* Submit request for a raw socket descriptor */
  if ((*sock_descr = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
   return 1;
  }

  const int on = 1;
  /* Set flag so socket expects us to provide IPv4 header */
  if (setsockopt(*sock_descr, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
   return 1;
  }

  return 0;
}

/* Function terminates pcap_loop() */
void terminate_process_TCP() {
   pcap_breakloop(handle);
}

/* Function handles incoming packet */
void tcp_handler_ip4(u_char *handler_return, const struct pcap_pkthdr *header, const u_char *packet) {
  (void) header;
  static int p_count = 1;
  struct tcphdr *tcph;

  tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + IP4_HDRLEN);

	if (tcph->th_flags & TH_RST) {
    *handler_return = PORT_CLOSED;
  }
  else if (tcph->th_flags & TH_ACK) {
    *handler_return = PORT_OPEN;
  }
  p_count++;
}

/* Function scanning TCP ports */
int tcp_scanner_ip4(SCAN_STRUC *scan_struc) {
  uint8_t *packet;
  struct ip iphdr;
  struct tcphdr tcphdr;
  struct sockaddr_in sin;

  packet = allocate_ustrmem_tcp(IP_MAXPACKET);

  fill_ip4_header_tcp(&iphdr, scan_struc);
  fill_tcp_header_ip4(&tcphdr, iphdr, scan_struc);

  memcpy(packet, &iphdr, IP4_HDRLEN * sizeof (uint8_t));
  memcpy((packet + IP4_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

  memset(&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;
  sin.sin_port = tcphdr.th_dport;

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
  if (create_ip4_tcp_socket(&sock_descr)) {
    return 1;
  }

  if (sendto(sock_descr, packet, IP4_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0)  {
    return 1;
  }

  struct bpf_program fp; // Compiled filter
  char filter[50];
  char filter_address[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(scan_struc->src_ipv4_address), filter_address, INET_ADDRSTRLEN);
  int filter_port = ntohs(tcphdr.th_sport);
  sprintf(filter, "dst host %s && dst port %d", filter_address, filter_port);

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

  signal(SIGALRM, terminate_process_TCP);
  alarm(2);

  unsigned char pcap_loop_ret = PORT_FILTERED;
  pcap_loop(handle, 1, tcp_handler_ip4, &pcap_loop_ret);
  if (pcap_loop_ret == PORT_CLOSED) {
    scan_struc->tcp_ports_result[scan_struc->tcp_port_index] = strdup("closed");
    if (scan_struc->tcp_ports_result[scan_struc->tcp_port_index] == NULL) {
      return 2;
    }
  }
  else if (pcap_loop_ret == PORT_OPEN) {
    scan_struc->tcp_ports_result[scan_struc->tcp_port_index] = strdup("open");
    if (scan_struc->tcp_ports_result[scan_struc->tcp_port_index] == NULL) {
      return 2;
    }
  }
  else if (pcap_loop_ret == PORT_FILTERED) {
    signal(SIGALRM, terminate_process_TCP);
    alarm(2);
    pcap_loop(handle, 1, tcp_handler_ip4, &pcap_loop_ret);
    scan_struc->tcp_ports_result[scan_struc->tcp_port_index] = strdup("filtered");
    if (scan_struc->tcp_ports_result[scan_struc->tcp_port_index] == NULL) {
      return 2;
    }
  }

  close(sock_descr);
  free(packet);
  pcap_close(handle);

  return 0;
}

/******************************************************************************/
/*                                    IPv6                                    */
/******************************************************************************/

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function compute checksum for TCP protocol */
uint16_t tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr) {
  uint32_t lvalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
  ptr += sizeof (iphdr.ip6_dst);
  chksumlen += sizeof (iphdr.ip6_dst);

  // Copy TCP length to buf (32 bits)
  lvalue = htonl (sizeof (tcphdr));
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);
  chksumlen += sizeof (lvalue);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  return checksum1((uint16_t *) buf, chksumlen);
}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function fills IPv6 protocol (TCP) */
void fill_ip6_header_tcp(struct ip6_hdr *iphdr, SCAN_STRUC *scan_struc) {
  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits): TCP header
  iphdr->ip6_plen = htons (TCP_HDRLEN);

  // Next header (8 bits): 6 for TCP
  iphdr->ip6_nxt = IPPROTO_TCP;

  // Hop limit (8 bits): default to maximum value
  iphdr->ip6_hops = 255;

  // Source IPv6 address (128 bits)
  iphdr->ip6_src = scan_struc->src_ipv6_address;

  // Destination IPv6 address (128 bits)
  iphdr->ip6_dst = scan_struc->dst_ipv6_address;

}

// Study source: http://www.pdbuchan.com/rawsock/rawsock.html
/* Function fills TCP header */
void fill_tcp_header_ip6(struct tcphdr *tcphdr, struct ip6_hdr iphdr, SCAN_STRUC *scan_struc) {
  int i, tcp_flags[8];

  // Source port number (16 bits)
  tcphdr->th_sport = htons(SRC_PORT);

  // Destination port number (16 bits)
  tcphdr->th_dport = htons(scan_struc->tcp_ports[scan_struc->tcp_port_index]);

  // Sequence number (32 bits)
  tcphdr->th_seq = htonl(0);

  // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
  tcphdr->th_ack = htonl(0);

  // Reserved (4 bits): should be 0
  tcphdr->th_x2 = 0;

  // Data offset (4 bits): size of TCP header in 32-bit words
  tcphdr->th_off = TCP_HDRLEN / 4;

  // FIN flag (1 bit)
  tcp_flags[0] = 0;

  // SYN flag (1 bit): set to 1
  tcp_flags[1] = 1;

  // RST flag (1 bit)
  tcp_flags[2] = 0;

  // PSH flag (1 bit)
  tcp_flags[3] = 0;

  // ACK flag (1 bit)
  tcp_flags[4] = 0;

  // URG flag (1 bit)
  tcp_flags[5] = 0;

  // ECE flag (1 bit)
  tcp_flags[6] = 0;

  // CWR flag (1 bit)
  tcp_flags[7] = 0;

  tcphdr->th_flags = 0;
  for (i = 0; i < 8; i++) {
    tcphdr->th_flags += (tcp_flags[i] << i);
  }

  // Window size (16 bits)
  tcphdr->th_win = htons(65535);

  // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr->th_urp = htons(0);

  // TCP checksum (16 bits)
  tcphdr->th_sum = tcp6_checksum(iphdr, *tcphdr);
}

/* Function creates TCP raw socket */
int create_ip6_tcp_socket(int *sock_descr) {
   if ((*sock_descr = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
       return 1;
   }

   const int on = 1;
   if (setsockopt (*sock_descr, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof (on)) < 0) {
       return 1;
   }

   return 0;
}

/* Function handles incoming packet */
void tcp_handler_ip6(u_char *handler_return, const struct pcap_pkthdr *header, const u_char *packet) {
  (void) header;

  static int p_count = 1;
  struct tcphdr *tcph;

  tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + IP6_HDRLEN);

	if (tcph->th_flags & TH_RST) {
    *handler_return = PORT_CLOSED;
  }
  else if (tcph->th_flags & TH_ACK) {
    *handler_return = PORT_OPEN;
  }
  p_count++;
}

/* Function scanning TCP ports */
int tcp_scanner_ip6(SCAN_STRUC *scan_struc) {
  uint8_t *packet;
  struct ip6_hdr iphdr;
  struct tcphdr tcphdr;
  struct sockaddr_in6 sin;

  packet = allocate_ustrmem_tcp(IP_MAXPACKET);

  fill_ip6_header_tcp(&iphdr, scan_struc);
  fill_tcp_header_ip6(&tcphdr, iphdr, scan_struc);

  memcpy(packet, &iphdr, IP6_HDRLEN * sizeof (uint8_t));
  memcpy((packet + IP6_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

  memset(&sin, 0, sizeof (struct sockaddr_in6));
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
  if (create_ip6_tcp_socket(&sock_descr)) {
    return 1;
  }
  int sendto_ret = sendto(sock_descr, packet, IP6_HDRLEN + TCP_HDRLEN, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr_in6));

  if (sendto_ret < 0) {
    return 1;
  }

  struct bpf_program fp; // Compiled filter
  char filter[50];
  char filter_address[INET_ADDRSTRLEN];
  inet_ntop(AF_INET6, &(scan_struc->src_ipv6_address), filter_address, INET_ADDRSTRLEN);
  int filter_port = ntohs(tcphdr.th_sport);
  sprintf(filter, "dst host %s && dst port %d", filter_address, filter_port);

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

  signal(SIGALRM, terminate_process_TCP);
  alarm(2);

  unsigned char pcap_loop_ret = PORT_FILTERED;
  pcap_loop(handle, 1, tcp_handler_ip6, &pcap_loop_ret);
  if (pcap_loop_ret == PORT_CLOSED) {
    scan_struc->tcp_ports_result[scan_struc->tcp_port_index] = strdup("closed");
    if (scan_struc->tcp_ports_result[scan_struc->tcp_port_index] == NULL) {
      return 2;
    }
  }
  else if (pcap_loop_ret == PORT_OPEN) {
    scan_struc->tcp_ports_result[scan_struc->tcp_port_index] = strdup("open");
    if (scan_struc->tcp_ports_result[scan_struc->tcp_port_index] == NULL) {
      return 2;
    }
  }
  else if (pcap_loop_ret == PORT_FILTERED) {
    signal(SIGALRM, terminate_process_TCP);
    alarm(2);
    pcap_loop(handle, 1, tcp_handler_ip6, &pcap_loop_ret);
    scan_struc->tcp_ports_result[scan_struc->tcp_port_index] = strdup("filtered");
    if (scan_struc->tcp_ports_result[scan_struc->tcp_port_index] == NULL) {
      return 2;
    }
  }

  close(sock_descr);
  free(packet);
  pcap_close(handle);

  return 0;
}
