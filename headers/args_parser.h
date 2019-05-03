/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      args_parser.h                                                   *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/
#ifndef _ARGS_PARSER_H_
#define _ARGS_PARSER_H_

/* Local modules */
#include "scan_struc.h"

/* Constans */
#define MACHINE_ID argv[argc-1]

/**
 * Function parse program arguments
 *
 * @param[in] argc Number of program arguments
 * @param[in] argv Program arguments
 * @param[in] scan_struc Main scanning structure
 * @return Function result
 */
int parse_args(int argc, char *argv[], SCAN_STRUC *scan_struc);

#endif /* _ARGS_PARSER_H_ */
