/**
 * zprd / routes.cxx - collection of via_route_t's
 * (C) 2017 - 2018 Erik Zscheile.
 * License: GPL-2+
 **/

#include "routes.hpp"
#include <algorithm>
#include <config.h> // zs_*likely

using namespace std;

via_router_t::via_router_t(const remote_peer_ptr_t &_addr, const uint8_t _hops) noexcept
  : addr(_addr), seen(last_time), latency(0), hops(_hops) { }

[[gnu::hot]]
auto route_via_t::find_router(const remote_peer_ptr_t &router) noexcept -> decltype(_routers)::iterator {
  return find_if(_routers.begin(), _routers.end(),
    [router](const via_router_t &i) noexcept
      { return i.addr == router || (*i.addr) == (*router); }
  );
}

static void update_hopcnt(uint8_t &oldhops, const uint8_t newhops) noexcept {
  if(newhops > oldhops)
    switch(newhops - oldhops) {
      case 0xbe:
      case 0xbf:
        return;
    }

  oldhops = newhops;
}

bool route_via_t::add_router(const remote_peer_ptr_t &router, const uint8_t hops) {
  if(empty()) _fresh_add = true;
  const auto it = find_router(router);
  const bool ret = (it == _routers.end());
  if(zs_unlikely(ret)) {
    _routers.emplace_front(router, hops);
  } else {
    it->seen = last_time;
    update_hopcnt(it->hops, hops);
  }
  return ret;
}

void route_via_t::update_router(const remote_peer_ptr_t &router, const uint8_t hops, const double latency) noexcept {
  const auto it = find_router(router);
  if(zs_unlikely(it == _routers.end())) return;
  it->seen = last_time;
  update_hopcnt(it->hops, hops);
  it->latency = latency;
}

bool route_via_t::del_router(const remote_peer_ptr_t &router) noexcept {
  bool ret = false;
  _routers.remove_if(
    [router, &ret](const via_router_t &a) noexcept -> bool {
      const bool tmp = (router == a.addr);
      ret |= tmp;
      return tmp;
    }
  );
  return ret;
}

#include <zprd_conf.hpp>

// deletes all outdated routers and sort routers
void route_via_t::cleanup(const std::function<void (const remote_peer_ptr_t&)> &f) {
  const auto ct = last_time - 2 * zprd_conf.remote_timeout;
  _routers.remove_if(
    [ct,&f](const via_router_t &a) {
      if(zs_likely(ct < a.seen || a.addr->is_local())) return false;
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

#include <stdlib.h>
#include <math.h>

/* swap_near_routers
   [FI] <- [SE] <- [TH]...
   --> [SE] <- [TH]... <- [FI] ...
 */
void route_via_t::swap_near_routers() noexcept {
  if(_routers.empty() || rand() % 2) return;

  const auto endit = _routers.cend();
  auto &primary = _routers.front();
  auto previt = _routers.cbegin(), it = previt;
  size_t near_rcnt = 0;
  for(++it; it != endit; ++it) {
    if(!zs_unlikely(it->hops <= primary.hops && fabs(it->latency - primary.latency) <= zprd_conf.max_near_rtt))
      break;
    ++previt;
    ++near_rcnt;
  }
  if(zs_likely(!near_rcnt)) return;

  /*
    1. backup HEAD + remove it from _routers
    2. recalculate previt
    3. put backup'ed HEAD after previt
   */

  auto primary_backup = move(primary);
  _routers.pop_front();
  previt = _routers.cbegin();
  std::advance(previt, near_rcnt - 1);
  _routers.emplace_after(previt, move(primary_backup));
}
