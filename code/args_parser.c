/******************************************************************************
 * Project:   2BIT IPK, Project 2                                             *
 *            Faculty of Information Technolgy                                *
 *            Brno University of Technology                                   *
 * File:      args_parser.c                                                   *
 * Date:      21.04.2019                                                      *
 * Author:    Peter Kruty, <xkruty00@stud.fit.vutbr.cz>                       *
 ******************************************************************************/

 /* Local modules */
#include "../headers/args_parser.h"
#include "../headers/help.h"
#include "../headers/scan_struc.h"

/* Standard libraries */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <regex.h>

/* Function gets ports from string to array of integers */
int get_ports_from_str(int **pint_ports, char *str_ports, int *ports_count) {
  regex_t regex_comma;
  regex_t regex_dash;
  regex_t regex_num_only;
  regex_t regex_num;
  regmatch_t match;
  int result;

  /* Compile regex */
  result = regcomp(&regex_dash, "^[0-9]+-[0-9]+$", REG_EXTENDED);
  if (result) {
    return 2;
  }
  result = regcomp(&regex_comma, "^([0-9]+,)+([0-9]+)$", REG_EXTENDED);
  if (result) {
    regfree(&regex_dash);
    return 2;
  }
  result = regcomp(&regex_num_only, "^[0-9]+$", REG_EXTENDED);
  if (result) {
    regfree(&regex_dash);
    regfree(&regex_comma);
    return 2;
  }

  result = regcomp(&regex_num, "[0-9]+", REG_EXTENDED);
  if (result) {
    regfree(&regex_dash);
    regfree(&regex_comma);
    regfree(&regex_num_only);
    return 2;
  }

  /* Execute regex */
  /* PORTS FORMAT: integer-integer */
  if (!regexec(&regex_dash, str_ports, 0, NULL, 0)) {
    int range[2];
    int i = 0;
    while(regexec(&regex_num, str_ports, 1, &match, 0) == 0)
    {
      char *str_num = malloc((match.rm_eo - match.rm_so)*sizeof(char) + 1);
      if (str_num == NULL) {
        regfree(&regex_comma);
        regfree(&regex_dash);
        regfree(&regex_num_only);
        regfree(&regex_num);
        return 2;
      }
      sprintf(str_num,"%.*s\n", (int)(match.rm_eo - match.rm_so), &str_ports[match.rm_so]); // Gets 1 port to string

      range[i] = (int) strtol(str_num, NULL, 10);
      i++;

      free(str_num);
      str_ports += match.rm_eo;
    }

    *ports_count = range[1] - range[0] + 1;

    if (range[0] < 0 || range[0] > 65535) {
      regfree(&regex_comma);
      regfree(&regex_dash);
      regfree(&regex_num_only);
      regfree(&regex_num);
      return 1;
    }
    if (range[1] < 0 || range[1] > 65535) {
      regfree(&regex_comma);
      regfree(&regex_dash);
      regfree(&regex_num_only);
      regfree(&regex_num);
      return 1;
    }

    /* Ports number randge */
    if (range[0] > range[1]) {
      regfree(&regex_comma);
      regfree(&regex_dash);
      regfree(&regex_num_only);
      regfree(&regex_num);
      return 1;
    }
    i = 0;
    for (int port = range[0]; port <= range[1]; port++) {
      i++;
      *pint_ports = realloc(*pint_ports, sizeof(int) * i + 1);
      if (*pint_ports == NULL) {
        regfree(&regex_comma);
        regfree(&regex_dash);
        regfree(&regex_num_only);
        regfree(&regex_num);
        return 2;
      }
      (*pint_ports)[i-1] = port;
    }
  }
  /* PORTS FORMAT: integer,integer,... */
  else if (!regexec(&regex_comma, str_ports, 0, NULL, 0)) {
    int i = 0;
    while(regexec(&regex_num, str_ports, 1, &match, 0) == 0)
    {
      char *str_num = malloc((match.rm_eo - match.rm_so)*sizeof(char) + 1);
      if (str_num == NULL) {
        regfree(&regex_comma);
        regfree(&regex_dash);
        regfree(&regex_num_only);
        regfree(&regex_num);
        return 2;
      }
      sprintf(str_num,"%.*s\n", (int)(match.rm_eo - match.rm_so), &str_ports[match.rm_so]); // Gets 1 port to string

      i++;
      *pint_ports = realloc(*pint_ports, sizeof(int) * i + 1);
      if (*pint_ports == NULL) {
        regfree(&regex_comma);
        regfree(&regex_dash);
        regfree(&regex_num_only);
        regfree(&regex_num);
        return 2;
      }
      (*pint_ports)[i-1] = (int) strtol(str_num, NULL, 10);  // Gets port from strin to string

      if ((*pint_ports)[i-1] < 0 || (*pint_ports)[i-1] > 65535) {
        regfree(&regex_comma);
        regfree(&regex_dash);
        regfree(&regex_num_only);
        regfree(&regex_num);
        return 1;
      }

      free(str_num);
      str_ports += match.rm_eo;

      (*ports_count)++;
    }
  }
  /* PORTS FORMAT: integer */
  else if (!regexec(&regex_num_only, str_ports, 0, NULL, 0)) {
    *pint_ports = (int *) malloc(sizeof(int)*2);
    if (*pint_ports == NULL) {
      regfree(&regex_comma);
      regfree(&regex_dash);
      regfree(&regex_num_only);
      regfree(&regex_num);
      return 2;
    }

    *ports_count = 1;

    (*pint_ports)[0] = (int) strtol(str_ports, NULL, 10);

    if ((*pint_ports)[0] < 0 || (*pint_ports)[0] > 65535) {
      regfree(&regex_comma);
      regfree(&regex_dash);
      regfree(&regex_num_only);
      regfree(&regex_num);
      return 1;
    }
  }
  /* WRONG PORTS FORMAT */
  else {
    regfree(&regex_comma);
    regfree(&regex_dash);
    regfree(&regex_num_only);
    regfree(&regex_num);
    return 1;
  }

  /* Free regex */
 	regfree(&regex_comma);
  regfree(&regex_dash);
  regfree(&regex_num_only);
  regfree(&regex_num);

  return 0;
}

/* Function parse program arguments */
int parse_args(int argc, char *argv[], SCAN_STRUC *scan_struc) {
  const char *optstring = "pt:u:hi:";
  int option;
  bool p_flag = false;
  int ref_argc = 2;
  opterr = 0; // GETOPT nevypisuje hlasky na stderr

  while ((option = getopt(argc, argv, optstring)) != -1) {
    switch (option) {
      case 'p':
        if (p_flag) {
          return 1;
        }
        else {
          p_flag = true;
        }
        break;

      /* Option -pt */
      case 't':
        if (!p_flag) {
          return 1;
        }
        else {
          if (get_ports_from_str(&(scan_struc->tcp_ports), optarg, &(scan_struc->tcp_ports_count))) {
            return 1;
          }

          scan_struc->tcp_ports_result = malloc(sizeof(char *) * (scan_struc->tcp_ports_count));
          if (scan_struc->tcp_ports_result == NULL) {
            return 2;
          }

          p_flag = false;
          ref_argc += 2;
        }
        break;

      /* Option -pu */
      case 'u':
        if (!p_flag) {
          return 1;
        }
        else {
          if (get_ports_from_str(&(scan_struc->udp_ports), optarg, &(scan_struc->udp_ports_count))) {
            return 1;
          }

          scan_struc->udp_ports_result = malloc(sizeof(char *) * (scan_struc->udp_ports_count));
          if (scan_struc->udp_ports_result == NULL) {
            return 2;
          }

          p_flag = false;
          ref_argc += 2;
        }
        break;
      /* option -i */
      case 'i':
        ref_argc += 2;
        scan_struc->src_interface = strdup(optarg);
        if (scan_struc->src_interface == NULL) {
          return 2;
        }
        break;
      /* option -h */
      case 'h':
        if (argc != 2) {
          return 1;
        }
        print_help();
        break;
    }
  }

  /* DNS/IP ADRESA */
  scan_struc->machine_id = strdup(MACHINE_ID);
  if (scan_struc->machine_id == NULL) {
    return 2;
  }

  /* Argc comparison */
  if (argc != ref_argc) {
    return 1;
  }

  return 0;
}
