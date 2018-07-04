/**
 * zprd_conf.hpp
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
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
};

extern zprd_conf_t zprd_conf;
