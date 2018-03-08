/**
 * crest.c
 * (C) 2017 Erik Zscheile
 * (C) 2006 Rheinwerk Verlag GmbH
 * License: GPL-3
 **/

#include "crest.h"

uint16_t in_cksum(const uint16_t *ptr, int nbytes) {
  register long sum = 0;

  for(; nbytes > 1; nbytes -= 2)
    sum += *(ptr++);

  if(nbytes)
    sum += * ((const uint8_t *) ptr);

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

void my_signal(const int sig_nr, const sighandler_t sig_handler) {
  struct sigaction newsig;
  newsig.sa_handler = sig_handler;
  newsig.sa_flags   = SA_RESTART;
  sigemptyset(&newsig.sa_mask);
  sigaction(sig_nr, &newsig, 0);
}
