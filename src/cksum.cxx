/**
 * cksum.cxx
 * (C) 2017 Erik Zscheile
 * License: GPL-3
 **/

#include "config.h"
#ifdef TBB_FOUND
# include <numeric>
# include <functional>
# include <tbb/parallel_reduce.h>
# include <tbb/blocked_range.h>
#endif
#include "crest.h"

uint16_t in_cksum(const uint16_t *ptr, int nbytes) noexcept {
  long sum = 0;

#ifdef TBB_FOUND
  if(nbytes > 1) {
    typedef tbb::blocked_range<const uint16_t*> tbr_t;
    const auto eob = ptr + (nbytes / 2);
    sum = tbb::parallel_reduce(
      tbr_t(ptr, eob), 0u,
      [](const tbr_t &r, const uint16_t x) noexcept {
        return std::accumulate(r.begin(), r.end(), x);
      }, std::plus<uint16_t>()
    );
    ptr = eob;
  }
#else
  for(; nbytes > 1; nbytes -= 2)
    sum += *(ptr++);
#endif

  if(nbytes % 1)
    sum += *reinterpret_cast<const uint8_t *>(ptr);

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}
