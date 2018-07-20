/**
 * cksum.cxx
 * (C) 2017 - 2018 Erik Zscheile
 * License: dual licensed under MIT and BSD-3-clause

 * NOTE: this file contains code derived from FreeBSD's ping.c

 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 **/

#include "config.h"
#include "crest.h"
#ifdef TBB_FOUND
# include <numeric>
# include <functional>
# include <tbb/parallel_reduce.h>
# include <tbb/blocked_range.h>
#endif

[[gnu::hot]]
uint16_t in_cksum(const uint16_t *ptr, int nbytes) noexcept {
  uint32_t sum = 0;

#ifdef TBB_FOUND
  if(nbytes > 1) {
    typedef tbb::blocked_range<const uint16_t*> tbr_t;
    const auto eob = ptr + (nbytes / 2);
    sum = tbb::parallel_reduce(
      tbr_t(ptr, eob), 0u,
      [](const tbr_t &r, const decltype(sum) x) noexcept {
        return std::accumulate(r.begin(), r.end(), x);
      }, std::plus<decltype(sum)>()
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
