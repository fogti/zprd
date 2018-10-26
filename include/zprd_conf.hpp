/**
 * zprd_conf.hpp
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <sys/socket.h>
#include <inttypes.h>
#include <time.h>
#include <string>
#include <vector>

struct zprd_conf_t {
  std::string iface;
  std::vector<std::string> remotes;

  // data port
  uint16_t data_port;

  // timeout in seconds after which remotes are silently discarded
  time_t remote_timeout;

  // latency, as in (|a.l - b.l|) <= max_near_rtt,
  // to consider two routers are near when considering one target
  // needed for multi-route-rand()
  uint16_t max_near_rtt;

  // preferred AF_* for resolve_...
  sa_family_t preferred_af;
};

extern zprd_conf_t zprd_conf;
