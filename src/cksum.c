/**
 * cksum.c
 * (C) 2017 - 2018 Erik Zscheile
 * License: dual licensed under MIT and BSD-3-clause

 * NOTE: this file contains code derived from FreeBSD's ping.c

 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 **/

#include "crest.h"

uint16_t __attribute__((hot)) in_cksum(const uint16_t *ptr, int nbytes) noexcept {
  uint32_t sum = 0;

  for(; nbytes > 1; nbytes -= 2)
    sum += *(ptr++);

  if(nbytes % 1)
    sum += *((uint8_t*)(ptr));

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}
