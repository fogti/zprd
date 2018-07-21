/**
 * zprd / routes.hpp
 * (C) 2017 - 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <forward_list>
#include <functional>
#include <tuple>

#include <addr_t.hpp>
#include "zprd_conf.hpp"

extern time_t last_time;

struct via_router_t final {
  zs_addr_t addr;
  time_t    seen;
  double    latency;
  uint8_t   hops;

  via_router_t(const zs_addr_t _addr, const uint8_t _hops) noexcept;
};

// collection of via_route_t's
class route_via_t final {
 public:
  std::forward_list<via_router_t> _routers;
  bool _fresh_add;

  route_via_t(): _fresh_add(false) { }

  // deletes all outdates routers and sort routers
  void cleanup(const std::function<void (const zs_addr_t)> &f);

  bool empty() const noexcept
    { return _routers.empty(); }

  zs_addr_t get_router() const noexcept
    { return _routers.front().addr; }

  // add or modify a router
  bool add_router(const zs_addr_t router, const uint8_t hops);

  void update_router(const zs_addr_t router, const uint8_t hops, const double latency) noexcept;

  /** replace_router:
   *
   * invariant: rold != rnew
   * timing:    O(n)      (all routers except if we reach both rold + rnew before)
   *
   * @param rold, rnew    old and new router addr
   **/
  void replace_router(const zs_addr_t rold, const zs_addr_t rnew) noexcept;

  bool del_router(const zs_addr_t router) noexcept;

  void del_primary_router() noexcept
    { _routers.pop_front(); }

 private:
  auto find_router(const zs_addr_t router) noexcept -> decltype(_routers)::iterator;
};
