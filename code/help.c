/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      help.c                                                          *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

/* Local modules */
#include "../headers/help.h"

/* Standard libraries */
#include <stdio.h>
#include <stdlib.h>

/* Function print help message */
void print_help() {
  printf(HELP_MSG);
  exit(0);
}
