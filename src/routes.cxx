/**
 * zprd / routes.cxx - collection of via_route_t's
 * (C) 2017 - 2018 Erik Zscheile.
 * License: GPL-3
 **/

#include <algorithm>
#include "routes.hpp"

using namespace std;

via_router_t::via_router_t(const uint32_t _addr, const uint8_t _hops) noexcept
  : addr(_addr), seen(last_time), latency(0), hops(_hops) { }

typedef std::forward_list<via_router_t> sfl_vrt;
auto tpl_find_router(sfl_vrt &c, const uint32_t router) -> sfl_vrt::iterator {
  return find_if(c.begin(), c.end(),
    [router](const via_router_t &i) noexcept {
      return i.addr == router;
    }
  );
}

bool route_via_t::add_router(const uint32_t router, const uint8_t hops) {
  if(empty()) _fresh_add = true;
  const auto it = tpl_find_router(_routers, router);
  const bool ret = (it == _routers.end());
  if(ret) {
    _routers.emplace_front(router, hops);
  } else {
    it->seen = last_time;
    it->hops = hops;
  }
  return ret;
}

void route_via_t::update_router(const uint32_t router, const uint8_t hops, const double latency) noexcept {
  const auto it = tpl_find_router(_routers, router);
  if(it == _routers.end()) return;
  it->seen = last_time;
  it->hops = hops;
  it->latency = latency;
}

/** replace_router:
 *
 * invariant: rold != rnew
 * timing:    O(n)      (all routers except if we reach both rold + rnew before)
 *
 * @param rold, rnew    old and new router addr
 **/
void route_via_t::replace_router(const uint32_t rold, const uint32_t rnew) noexcept {
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

bool route_via_t::del_router(const uint32_t router) noexcept {
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
