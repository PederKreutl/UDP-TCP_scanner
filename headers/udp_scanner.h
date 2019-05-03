/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      udp_scanner.h                                                   *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/
#ifndef _UDP_SCANNER_H_
#define _UDP_SCANNER_H_

/* Local modules */
#include "scan_struc.h"

/* Network libraries */
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

/**
 * Function scans UDP ports on machine with IPv4
 *
 * @param[in] scan_struc Main scanning structure
 * @return Function result
 */
int udp_scanner_ip4(SCAN_STRUC *scan_struc);

/**
 * Function scans UDP ports on machine with IPv6
 *
 * @param[in] scan_struc Main scanning structure
 * @return Function result
 */
int udp_scanner_ip6(SCAN_STRUC *scan_struc);

#endif /* _UDP_SCANNER_H_ */
