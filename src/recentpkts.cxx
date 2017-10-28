/** recentpkts.cxx loop detection using round-robin alike database of recent
 *                 packet ids
 * (C) 2017 Erik Zscheile
 * License: GPL-3
 **/

#include <unordered_map>
#include "recentpkts.hpp"

static std::unordered_map<uint64_t, uint8_t> _pkts;

bool RecentPkts_append(const uint64_t id) {
  bool ret = false;

  // drop expired pkts + aging + found?
  for(auto it = _pkts.begin(); it != _pkts.end(); ) {
    if(!it->second) {
      it = _pkts.erase(it);
      continue;
    }

    // packet found ?
    ret = ret || (it->first == id);

    --(it->second);
    ++it;
  }

  // append if unknown + reset ttl
  _pkts[id] = 32;

  return ret;
}
