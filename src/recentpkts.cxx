/** recentpkts.cxx loop detection using round-robin alike database of recent
 *                 packet ids
 * (C) 2017 Erik Zscheile
 * License: GPL-3
 **/

#include <unordered_map>
#include "recentpkts.hpp"

static std::unordered_map<uint64_t, uint8_t> _pkts;

bool RecentPkts_append(const uint64_t &id) {
  // drop expired pkts + aging
  for(auto it = _pkts.begin(); it != _pkts.end(); ) {
    if(!it->second) {
      it = _pkts.erase(it);
    } else {
      --(it->second);
      ++it;
    }
  }

  // packet found
  const bool ret = (_pkts.count(id) == 1);

  // append if unknown + reset ttl
  _pkts[id] = 32;

  return ret;
}
