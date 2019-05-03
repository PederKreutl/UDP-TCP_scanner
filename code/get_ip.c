/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      get_ip.c                                                        *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

/* Local modules */
#include "../headers/get_ip.h"
#include "../headers/scan_struc.h"

/* Standard libraries */
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

/* Network libraries */
#include <sys/socket.h>
#include <netdb.h> // getaddrinfo()
#include <netinet/in.h> // struct sockaddr_in/sockaddr_in6
#include <arpa/inet.h> // pton()
#include <pcap.h> // libpcap


/* Function differentiates IPv4, IPv6 and domain name, but not verifies them */
int parse_machine_id(char *machine_id) {
  bool domain_name_flag = false;
  bool ipv6_flag = false;

  char c;
  for(int i = 0;(c = machine_id[i]) != '\0'; i++) {
    if ((!isdigit(c)) && (c != ':') && (c != '.')) {
      if ((c >= 'a') && (c <= 'f')) {
        continue;
      }
      domain_name_flag = true;
    }
    if (c == ':') {
      ipv6_flag = true;
    }
  }

  if (domain_name_flag) {
    return DOMAIN_NAME;
  }
  else if (ipv6_flag) {
    return IPV6_TYPE;
  }
  else {
    return IPV4_TYPE;
  }
}

/* Function translate machine id to the IP address */
int get_dst_ip(SCAN_STRUC *scan_struc) {
  int id_type = parse_machine_id(scan_struc->machine_id);

  if (id_type == DOMAIN_NAME) {
    struct addrinfo *result;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    int ip_result = getaddrinfo(scan_struc->machine_id, NULL, &hints, &result);

    /* Function failed */
    if (ip_result != 0) {
      return 1;
    }

    /* Finding the right address */
    struct addrinfo *rp;
    int sfd;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
      sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      /* Not success */
      if (sfd == -1) {
       continue;
      }
      /* Success */
      if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
         break;
       }
        close(sfd);
      }

      /* No address succeeded */
      if (rp == NULL) {
        return 1;
    }

    /* Closing succeeded socket */
    close(sfd);

    if (rp->ai_family == AF_INET) {
      struct sockaddr_in* saddr = (struct sockaddr_in*)rp->ai_addr;
      scan_struc->dst_ip_address = inet_ntoa(saddr->sin_addr);
      scan_struc->dst_ipv4_address = saddr->sin_addr;
      scan_struc->dst_ip_type = IPV4_TYPE;
    }
    else if (rp->ai_family == AF_INET6) {
      struct sockaddr_in6* saddr = (struct sockaddr_in6*)rp->ai_addr;
      inet_ntop(AF_INET6, &(saddr->sin6_addr), scan_struc->dst_ip_address, INET6_ADDRSTRLEN);
      scan_struc->dst_ipv6_address = saddr->sin6_addr;
      scan_struc->dst_ip_type = IPV6_TYPE;
    }
    else {
      return 1;
    }

    /* No longer needed */
    freeaddrinfo(result);

    scan_struc->domain_name_flag = true;
    return 0;
  }
  /* IPv4 address, translation not needed */
  else if (id_type == IPV4_TYPE) {
    int ip_result = inet_pton(AF_INET, scan_struc->machine_id, &(scan_struc->dst_ipv4_address));
    if (ip_result <= 0) {
      if (!ip_result) {
        return 1;
      }
      else {
        return 2;
      }
    }
    scan_struc->dst_ip_address = scan_struc->machine_id;

    scan_struc->dst_ip_type = IPV4_TYPE;
    scan_struc->domain_name_flag = false;
    return 0;
  }
  /* IPv6 address, translation not needed */
  else if (id_type == IPV6_TYPE) {
    int ip_result = inet_pton(AF_INET6, scan_struc->machine_id, &(scan_struc->dst_ipv6_address));
    if (ip_result <= 0) {
      if (!ip_result) {
        return 1;
      }
      else {
        return 2;
      }
    }
    scan_struc->dst_ip_address = scan_struc->machine_id;

    scan_struc->dst_ip_type = IPV6_TYPE;
    scan_struc->domain_name_flag = false;
    return 0;
  }

  return 1;
}

int get_src_ip(SCAN_STRUC *scan_struc) {
  /* Destination IP address == IPv4 */
  if (scan_struc->dst_ip_type == IPV4_TYPE) {
    /* Bol zadany source interface */
    if (scan_struc->src_interface) {

      bool lo_flag = false;
      char is_localhost[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(scan_struc->dst_ipv4_address), is_localhost, INET_ADDRSTRLEN);

      if (strcmp(is_localhost, "127.0.0.1") == 0) {
        lo_flag = true;
      }

      pcap_if_t *alldevs;
      char errbuf[PCAP_ERRBUF_SIZE];
      int status = pcap_findalldevs(&alldevs, errbuf);
      if(status != 0) {
          return 1;
      }
      for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
          for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
              if((a->addr->sa_family == AF_INET) && (!strcmp(scan_struc->src_interface,d->name))) {
                if (!(d->flags & PCAP_IF_LOOPBACK) && (lo_flag)) {
                  continue;
                }
                scan_struc->src_ipv4_address = ((struct sockaddr_in*)a->addr)->sin_addr;

                pcap_freealldevs(alldevs);
                return 0;
              }
          }
      }
      pcap_freealldevs(alldevs);

      return 1;
    }
    /* Nebol zadany source interface */
    else {
      bool lo_flag = false;

      char is_localhost[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &(scan_struc->dst_ipv4_address), is_localhost, INET_ADDRSTRLEN);

      if (strcmp(is_localhost, "127.0.0.1") == 0) {
        int ip_result = inet_pton(AF_INET, "127.0.0.1", &(scan_struc->src_ipv4_address));
        if (ip_result <= 0) {
          if (!ip_result) {
            return 1;
          }
          else {
            return 2;
          }
        }
        lo_flag = true;
      }

      pcap_if_t *alldevs;
      char errbuf[PCAP_ERRBUF_SIZE];
      int status = pcap_findalldevs(&alldevs, errbuf);
      if(status != 0) {
          return 1;
      }
      for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
          for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
              if (lo_flag) {
                if((a->addr->sa_family == AF_INET) && (d->flags & PCAP_IF_LOOPBACK)) { // local host
                  scan_struc->src_ipv4_address = ((struct sockaddr_in*)a->addr)->sin_addr;
                  scan_struc->src_interface = strdup(d->name);
                  if (scan_struc->src_interface == NULL) {
                    return 2;
                  }
                  pcap_freealldevs(alldevs);
                  return 0;
                }
              }
              else {
                if ((a->addr->sa_family == AF_INET) && (d->flags & PCAP_IF_RUNNING) && !(d->flags & PCAP_IF_LOOPBACK)) {
                  scan_struc->src_ipv4_address = ((struct sockaddr_in*)a->addr)->sin_addr;
                  scan_struc->src_interface = strdup(d->name);
                  if (scan_struc->src_interface == NULL) {
                    return 2;
                  }
                  pcap_freealldevs(alldevs);
                  return 0;
                }
              }
          }
      }
      pcap_freealldevs(alldevs);

      return 1;
    }

  }
  /* Destination IP address == IPv6 */
  else {
    /* Source interface was entered */
    if (scan_struc->src_interface) {

      bool lo_flag = false;
      char is_localhost[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &(scan_struc->dst_ipv6_address), is_localhost, INET6_ADDRSTRLEN);

      if (strcmp(is_localhost, "::1") == 0) {
        lo_flag = true;
      }

      pcap_if_t *alldevs;
      char errbuf[PCAP_ERRBUF_SIZE];
      int status = pcap_findalldevs(&alldevs, errbuf);
      if(status != 0) {
          return 1;
      }
      for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
          for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
              if((a->addr->sa_family == AF_INET6) && (!strcmp(scan_struc->src_interface,d->name))) {
                scan_struc->src_ipv6_address = ((struct sockaddr_in6*)a->addr)->sin6_addr;
                if (!(d->flags & PCAP_IF_LOOPBACK) && (lo_flag)) {
                  continue;
                }
                else if (IN6_IS_ADDR_LINKLOCAL(&(((struct sockaddr_in6*)a->addr)->sin6_addr)) && !(lo_flag)) {
                    continue;
                }

                pcap_freealldevs(alldevs);

                return 0;
              }
          }
      }
      pcap_freealldevs(alldevs);

      return 1;
    }
    /* Nebol zadany source interface */
    else {
      bool lo_flag = false;

      char is_localhost[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &(scan_struc->dst_ipv6_address), is_localhost, INET6_ADDRSTRLEN);

      if (strcmp(is_localhost, "::1") == 0) {
        int ip_result = inet_pton(AF_INET6, "0:0:0:0:0:0:0:1", &(scan_struc->src_ipv6_address));
        if (ip_result <= 0) {
          if (!ip_result) {
            return 1;
          }
          else {
            return 2;
          }
        }

        lo_flag = true;
      }

      pcap_if_t *alldevs;
      char errbuf[PCAP_ERRBUF_SIZE];
      int status = pcap_findalldevs(&alldevs, errbuf);
      if(status != 0) {
          return 1;
      }
      for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
          for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
              if (lo_flag) {
                if((a->addr->sa_family == AF_INET6) && (d->flags & PCAP_IF_LOOPBACK)) { // local host
                  scan_struc->src_ipv6_address = ((struct sockaddr_in6*)a->addr)->sin6_addr;
                  scan_struc->src_interface = strdup(d->name);
                  if (scan_struc->src_interface == NULL) {
                    return 2;
                  }
                  pcap_freealldevs(alldevs);
                  return 0;
                }
              }
              else {
                if ((a->addr->sa_family == AF_INET6) && (d->flags & PCAP_IF_RUNNING) && !(d->flags & PCAP_IF_LOOPBACK)) {
                  if (IN6_IS_ADDR_LINKLOCAL(&(((struct sockaddr_in6*)a->addr)->sin6_addr))) {
                    continue;
                  }
                  scan_struc->src_ipv6_address = ((struct sockaddr_in6*)a->addr)->sin6_addr;
                  scan_struc->src_interface = strdup(d->name);
                  if (scan_struc->src_interface == NULL) {
                    return 2;
                  }
                  pcap_freealldevs(alldevs);
                  return 0;
                }
              }
          }
      }
      pcap_freealldevs(alldevs);
      return 1;
    }

    return 1;
  }
}
