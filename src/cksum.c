/**
 * cksum.c
 * (C) 2017 Erik Zscheile.
 * License: GPL-3
 **/

#include "cksum.h"

uint16_t in_cksum(const uint16_t *ptr, int nbytes) {
  register long sum = 0;

  for(; nbytes > 1; nbytes -= 2) {
    sum += *ptr;
    ++ptr;
  }

  if(nbytes == 1) {
    const uint8_t oddbyte = * ((const uint8_t *) ptr);
    sum += oddbyte;
  }

  while(sum >> 16)
    sum = (sum >> 16) + (sum & 0xffff);

  return ~sum;
}

uint64_t in_hashsum(const uint8_t *ptr, uint16_t nbytes) {
  register uint64_t sum = 0;

  while(nbytes) {
    sum += *ptr << ((nbytes % 8) * 8);
    ++ptr; --nbytes;
  }

  return ~sum;
}
