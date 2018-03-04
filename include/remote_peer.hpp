/**
 * remote_peer.hpp
 * (C) 2017 Erik Zscheile.
 * License: GPL-3
 **/
#ifndef REMOTE_PEER_HPP
# define REMOTE_PEER_HPP 1
# include <inttypes.h>
# include <stdint.h>
# include <time.h>
struct remote_peer_t {
  time_t   seen;
  intmax_t cent; // config entry

  remote_peer_t() noexcept;
  remote_peer_t(const size_t cfgent) noexcept;
  void refresh() noexcept;
  const char *cfgent_name() const;
};
#endif
