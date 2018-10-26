/**
 * zprd / routes.hpp
 * (C) 2017 - 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include "remote_peer.hpp"

extern time_t last_time;

struct via_router_t final {
  remote_peer_ptr_t addr;
  time_t  seen;
  double  latency;
  uint8_t hops;

  via_router_t(const remote_peer_ptr_t &_addr, const uint8_t _hops) noexcept;
};

#include <forward_list>
#include <functional>

// collection of via_route_t's
class route_via_t final {
 public:
  std::forward_list<via_router_t> _routers;
  bool _fresh_add;

  route_via_t(): _fresh_add(false) { }

  // deletes all outdates routers and sort routers
  void cleanup(const std::function<void (const remote_peer_ptr_t&)> &f);

  bool empty() const noexcept
    { return _routers.empty(); }

  auto get_router() const noexcept
    { return _routers.front().addr; }

  // add or modify a router
  bool add_router(const remote_peer_ptr_t &router, const uint8_t hops);
  void update_router(const remote_peer_ptr_t &router, const uint8_t hops, const double latency) noexcept;

  // del_router: ASYMMETRY WARNING: deletes *exactly* this router pointer
  bool del_router(const remote_peer_ptr_t &router) noexcept;

  void del_primary_router() noexcept
    { _routers.pop_front(); }

  void swap_near_routers() noexcept;

 private:
  auto find_router(const remote_peer_ptr_t &router) noexcept -> decltype(_routers)::iterator;
};
