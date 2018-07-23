/**
 * ping_cache.hpp
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <addr_t.hpp>

class ping_cache_t final {
 public:
  struct match_t final {
    double diff;
    zs_addr_t router;
    uint8_t hops;
    bool match;
  };

  struct data_t final {
    zs_addr_t src, dst;
    uint16_t id, seq;

    data_t(const zs_addr_t _src = 0, const zs_addr_t _dst = 0,
           const uint16_t _id = 0, const uint16_t _seq = 0) noexcept
      : src(_src), dst(_dst), id(_id), seq(_seq) { }
  };

 private:
  double _seen;
  data_t _dat;
  zs_addr_t _router;

  static double get_ms_time() noexcept;

 public:
  ping_cache_t() noexcept: _seen(0), _router(0) { }

  void init(const data_t &dat, const zs_addr_t router) noexcept;
  auto match(const data_t &dat, const zs_addr_t router, const uint8_t ttl)
       noexcept -> match_t;
};
