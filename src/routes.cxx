/**
 * zprd / routes.cxx - collection of via_route_t's
 * (C) 2017 - 2018 Erik Zscheile.
 * License: GPL-2+
 **/

#include <algorithm>
#include "routes.hpp"
#include <config.h>

using namespace std;

via_router_t::via_router_t(const remote_peer_ptr_t &_addr, const uint8_t _hops) noexcept
  : addr(_addr), seen(last_time), latency(0), hops(_hops) { }

// deletes all outdates routers and sort routers
void route_via_t::cleanup(const std::function<void (const remote_peer_ptr_t&)> &f) {
  const auto ct = last_time - 2 * zprd_conf.remote_timeout;
  _routers.remove_if(
    [ct,&f](const via_router_t &a) {
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

[[gnu::hot]]
auto route_via_t::find_router(const remote_peer_ptr_t &router) noexcept -> decltype(_routers)::iterator {
  return find_if(_routers.begin(), _routers.end(),
    [router](const via_router_t &i) noexcept
      { return i.addr == router; }
  );
}

static void update_hopcnt(uint8_t &oldhops, const uint8_t newhops) {
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

/** replace_router:
 *
 * invariant: rold != rnew
 * timing:    O(n)      (all routers except if we reach both rold + rnew before)
 *
 * @param rold, rnew    old and new router addr
 **/
void route_via_t::replace_router(const remote_peer_ptr_t &rold, const remote_peer_ptr_t &rnew) noexcept {
  const auto it_e = _routers.end();
  auto it_ob = it_e; // (iterator to old router) - 1
  bool nf = true;    // new router not found?

  for(auto it = _routers.begin(), itb = _routers.before_begin(); it != it_e; ++it, ++itb) {
    if(it->addr == rold)
      it_ob = itb;
    else if(it->addr == rnew)
      nf = false;
    else
      continue;

    if(!(nf || it_ob == it_e))
      break;
  }

  if(it_ob == it_e) {
    // found [!o ?n]
  } else if(nf) {
    // found [o !n]
    ++it_ob;
    it_ob->addr = rnew;
  } else {
    // found [o n]
    _routers.erase_after(it_ob);
  }
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
