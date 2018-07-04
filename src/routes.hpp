/**
 * zprd / routes.hpp
 * (C) 2017 - 2018 Erik Zscheile.
 * License: GPL-3
 **/
#pragma once
#include <inttypes.h>
#include <forward_list>
#include <tuple>
#include "zprd_conf.hpp"

extern time_t last_time;

struct via_router_t final {
  uint32_t addr;
  time_t   seen;
  double   latency;
  uint8_t  hops;

  via_router_t(const uint32_t _addr, const uint8_t _hops) noexcept;
};

// collection of via_route_t's
struct route_via_t final {
  std::forward_list<via_router_t> _routers;
  bool _fresh_add;

  route_via_t(): _fresh_add(false) { }

  // deletes all outdates routers and sort routers
  template<typename Fn>
  void cleanup(const Fn f) {
    const auto ct = last_time - 2 * zprd_conf.remote_timeout;
    _routers.remove_if(
      [ct,f](const via_router_t &a) {
        if(ct < a.seen) return false;
        f(a.addr);
        return true;
      }
    );

    _routers.sort(
      // place best router in front: low hops, low latency, recent seen
      // priority high to low: hop count > latency > seen time
      [](const via_router_t &a, const via_router_t &b) noexcept {
        return std::tie(a.hops, a.latency, b.seen) < std::tie(b.hops, b.latency, a.seen);
      }
    );
  }

  bool empty() const noexcept {
    return _routers.empty();
  }

  uint32_t get_router() const noexcept {
    return _routers.front().addr;
  }

  // add or modify a router
  bool add_router(const uint32_t router, const uint8_t hops);

  void update_router(const uint32_t router, const uint8_t hops, const double latency) noexcept;

  /** replace_router:
   *
   * invariant: rold != rnew
   * timing:    O(n)      (all routers except if we reach both rold + rnew before)
   *
   * @param rold, rnew    old and new router addr
   **/
  void replace_router(const uint32_t rold, const uint32_t rnew) noexcept;

  bool del_router(const uint32_t router) noexcept;

  void del_primary_router() noexcept {
    _routers.pop_front();
  }
};
