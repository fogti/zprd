/**
 * zsig.c
 * (C) 2017 Erik Zscheile
 * (C) 2006 Rheinwerk Verlag GmbH
 * License: GPL-3
 **/

#include "crest.h"

void my_signal(const int sig_nr, const sighandler_t sig_handler) {
  struct sigaction newsig;
  newsig.sa_handler = sig_handler;
  newsig.sa_flags   = SA_RESTART;
  sigemptyset(&newsig.sa_mask);
  sigaction(sig_nr, &newsig, 0);
}
