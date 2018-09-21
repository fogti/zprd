/**
 * zprd / sender.hpp
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include "remote_peer.hpp"
#include "zprn.hpp"

#include <thread>
#include <vector>

// helper classes

struct send_data final {
  std::vector<char> buffer;
  std::vector<remote_peer_ptr_t> dests;
  uint32_t tos;
  uint16_t frag;

  send_data() noexcept: tos(0), frag(0) { }

  send_data(const send_data &o) = default;

  send_data(send_data &&o) noexcept
    : buffer(std::move(o.buffer)), dests(std::move(o.dests)),
      tos(o.tos), frag(o.frag) { }

  send_data(std::vector<char> &&buf, decltype(dests) &&d,
            const uint16_t frag_ = 0, const uint32_t tos_ = 0) noexcept
    : buffer(std::move(buf)), dests(std::move(d)), tos(tos_), frag(frag_) { }

  send_data& operator=(const send_data &o) = default;

  send_data& operator=(send_data &&o) noexcept {
    if(this != &o) {
      buffer = std::move(o.buffer);
      dests  = std::move(o.dests);
      frag   = o.frag; tos = o.tos;
    }
    return *this;
  }
};

struct zprn2_sdat {
  zprn_v2 zprn;
  std::vector<remote_peer_ptr_t> dests;

  zprn2_sdat(const zprn2_sdat &o) = default;
  zprn2_sdat(zprn2_sdat &&o) noexcept
    : zprn(o.zprn), dests(std::move(o.dests)) { }

  zprn2_sdat(const zprn_v2 &zprn_, decltype(dests) &&d) noexcept
    : zprn(zprn_), dests(std::move(d)) { }

  zprn2_sdat& operator=(const zprn2_sdat &o) = default;

  zprn2_sdat& operator=(zprn2_sdat &&o) noexcept {
    if(this != &o) {
      zprn  = o.zprn;
      dests = std::move(o.dests);
    }
    return *this;
  }
};

// main sender class

class sender_t final {
  std::vector<send_data> _tasks;
  std::vector<zprn2_sdat> _zprn_msgs;

  // sync
  std::mutex _mtx;
  std::condition_variable _cond;
  bool _stop = false;

  void worker_fn() noexcept;

 public:
  ~sender_t() noexcept { stop(); }

  void enqueue(send_data &&dat);
  void enqueue(zprn2_sdat &&dat);
  void start();
  void stop() noexcept;
};
