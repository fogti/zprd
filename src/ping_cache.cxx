/**
 * ping_cache.cxx determinate latency and hop count using a ping cache
 * (C) 2018 Erik Zscheile.
 * License: GPL-3
 **/

#include <time.h>
#include <tuple>
#include "ping_cache.hpp"

// TODO: handle failure of clock_gettime
double ping_cache_t::get_ms_time() noexcept {
  struct timespec curt;
  clock_gettime(CLOCK_MONOTONIC, &curt);
  return curt.tv_sec * 1000 + curt.tv_nsec / 1000000.0;
}

void ping_cache_t::init(const data_t &dat, const uint32_t router) noexcept {
  _seen   = get_ms_time();
  _dat    = dat;
  _router = router;
}

auto ping_cache_t::match(const data_t &dat, const uint32_t router, const uint8_t ttl) noexcept -> match_t {
  // NOTE: src and dst are swapped between a and b
  if(_seen && std::tie( router,  dat.src,  dat.dst,  dat.id,  dat.seq) ==
              std::tie(_router, _dat.dst, _dat.src, _dat.id, _dat.seq)) {
    const match_t ret = { get_ms_time() - _seen, dat.src, router, uint8_t(65 - ttl), true };
    _seen = 0;
    _dat.seq = 0;
    return ret;
  } else {
    return { 1, 0, 0, 255, false };
  }
}
