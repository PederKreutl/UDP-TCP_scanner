/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      get_ip.h                                               *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/
#ifndef _DOM_NAME_TRANSL_H_
#define _DOM_NAME_TRANSL_H_

/* Local modules */
#include "scan_struc.h"

/**
 * Function gets destination IP
 *
 * @param[in] scan_struc Main scanning structure
 * @return Function result
 */
int get_dst_ip(SCAN_STRUC *scan_struc);

/**
 * Function gets source IP
 *
 * @param[in] scan_struc Main scanning structure
 * @return Function result
 */
int get_src_ip(SCAN_STRUC *scan_struc);

#endif /* _DOM_NAME_TRANSL_H_ */
