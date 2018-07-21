/**
 * remote_peer.hpp
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <inttypes.h>
#include <stddef.h>
#include <time.h>

struct remote_peer_t {
  time_t seen;
  size_t cent; // config entry
  bool to_discard; // should this entry be deleted in the next cleanup round?

  remote_peer_t() noexcept;
  remote_peer_t(const size_t cfgent) noexcept;
  const char *cfgent_name() const noexcept;
};
