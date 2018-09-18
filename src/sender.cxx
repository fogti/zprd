/**
 * zprd / sender.cxx
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/

#define __USE_MISC 1
#include <sys/types.h>
#include "sender.hpp"
#include "crest.h"
#include <stdio.h>       // perror
#include <unistd.h>      // write
#include <sys/prctl.h>   // prctl
#include <netinet/ip.h>  // struct ip, IP_*

using namespace std;

void sender_t::enqueue(send_data &&dat) {
  // sanitize dat.dests
  if(dat.dests.empty())
    return;
  if(*dat.dests.front() == remote_peer_t())
    dat.dests.clear();
  dat.dests.shrink_to_fit();

  // move into queue
  {
    lock_guard<mutex> lock(_mtx);
    _tasks.emplace_back(move(dat));
  }
  _cond.notify_one();
}

void sender_t::enqueue(zprn2_sdat &&dat) {
  // sanitize dat.dests
  if(dat.dests.empty())
    return;
  dat.dests.shrink_to_fit();

  // move into queue
  {
    lock_guard<mutex> lock(_mtx);
    _zprn_msgs.emplace_back(move(dat));
  }
  _cond.notify_one();
}

void sender_t::start() {
  {
    lock_guard<mutex> lock(_mtx);
    _stop = false;
  }
  thread(&sender_t::worker_fn, this).detach();
}

void sender_t::stop() noexcept {
  {
    lock_guard<mutex> lock(_mtx);
    _stop = true;
  }
  _cond.notify_all();
}

#include <unordered_map>

/** file descriptors
 *
 * local_fd   = the tun device
 * server_fds = the server udp sockets
 **/
extern int local_fd;
extern unordered_map<sa_family_t, int> server_fds;

void sender_t::worker_fn() noexcept {
  // create a backup
  const auto my_server_fds = server_fds;

  const auto sendto_peer = [&my_server_fds](const remote_peer_ptr_t &i, const char * const buf, const size_t buflen) noexcept -> bool {
    return i->locked_crun([&](const remote_peer_t &o) noexcept {
      if(sendto(my_server_fds.at(o.saddr.ss_family), buf, buflen, 0, reinterpret_cast<const struct sockaddr *>(&o.saddr), sizeof(o.saddr)) < 0) {
        perror("sendto()");
        return false;
      }
      return true;
    });
  };

  prctl(PR_SET_NAME, "sender", 0, 0, 0);

  bool df = false;
  uint8_t tos = 0;

  const auto set_df = [&](const bool cdf) noexcept {
    const int tmp_df = cdf
# if defined(IP_DONTFRAG)
      ;
    if(setsockopt(my_server_fds.at(AF_INET), IPPROTO_IP, IP_DONTFRAG, &tmp_df, sizeof(tmp_df)) < 0)
      perror("SENDER WARNING: setsockopt(IP_DONTFRAG) failed");
# elif defined(IP_MTU_DISCOVER)
      ? IP_PMTUDISC_WANT : IP_PMTUDISC_DONT;
    if(setsockopt(my_server_fds.at(AF_INET), IPPROTO_IP, IP_MTU_DISCOVER, &tmp_df, sizeof(tmp_df)) < 0)
      perror("SENDER WARNING: setsockopt(IP_MTU_DISCOVER) failed");
# else
#  warning "set_ip_df: no method available to manage the dont-frag bit"
      ;
    if(0) {}
# endif
    else df = cdf;
  };

  const auto set_tos = [&](const uint8_t ctos) noexcept {
    if(setsockopt(my_server_fds.at(AF_INET), IPPROTO_IP, IP_TOS, &ctos, 1) < 0)
      perror("SENDER WARNING: setsockopt(IP_TOS) failed");
    else tos = ctos;
  };

  set_df(false);
  set_tos(0);

  vector<send_data> tasks;
  vector<zprn2_sdat> zprn_msgs;
  unordered_map<remote_peer_ptr_t, vector<vector<char>>> zprn_buf;
  vector<char> zprn_hdrv(sizeof(zprn_v2hdr), 0);
  {
    const auto h_zprn = reinterpret_cast<zprn_v2hdr *>(zprn_hdrv.data());
    h_zprn->zprn_ver = 2;
  }

  while(true) {
    {
      unique_lock<mutex> lock(_mtx);
      _cond.wait(lock, [this] { return _stop || !(_tasks.empty() && _zprn_msgs.empty()); });
      if(_tasks.empty() && _zprn_msgs.empty()) return;
      tasks = move(_tasks);
      _tasks = {};
      zprn_msgs = move(_zprn_msgs);
      _zprn_msgs = {};
    }

    bool got_error = false;

    // send normal data
    for(auto &dat: tasks) {
      auto buf = dat.buffer.data();
      const auto buflen = dat.buffer.size();

      // send data
      // NOTE: it is impossible that local_ip and others are destinations together
      if(dat.dests.empty()) {
        { // update checksum if ipv4
          const auto h_ip = reinterpret_cast<struct ip*>(buf);
          if(buflen >= sizeof(struct ip) && h_ip->ip_v == 4)
            h_ip->ip_sum = IN_CKSUM(h_ip);
        }
        if(write(local_fd, buf, buflen) < 0) {
          got_error = true;
          perror("write()");
        }
        continue;
      }

      // detect if we need to set the df and tos bits
      for(const auto &i : dat.dests)
        if(i->get_saddr().ss_family == AF_INET)
          goto cont_ipv4hs;
      goto cont_nohs;

     cont_ipv4hs:
      { // setup outer Dont-Frag bit
        const bool cdf = dat.frag & htons(IP_DF);
        if(df != cdf) set_df(cdf);
      }

      // setup outer TOS
      if(tos != dat.tos) set_tos(dat.tos);

     cont_nohs:
      for(const auto &i : dat.dests)
        if(!sendto_peer(i, buf, buflen))
          got_error = true;
    }

    if(zprn_msgs.empty()) goto flush_stdstreams;
    tasks.clear();

    // setup outer Dont-Frag bit + TOS
    if(df)  set_df(false);
    if(tos) set_tos(0);

    // build ZPRN v2 messages for each destination
    // NOTE: split zprn packet in multiple parts if it exceeds a certain size (e.g. 1232 bytes = 35 packets in worst case),
    //  but it is irrealistic, that this happens.
    //  This is important because IPv6 doesn't perform fragmentation.
    for(auto &i : zprn_msgs) {
      const size_t zmsiz = i.zprn.get_needed_size();
      zprn_buf.reserve(i.dests.size());
      {
        auto &x = i.zprn.route.type;
        x = htons(x);
      }
      const char *const zmbeg = reinterpret_cast<const char *>(&i.zprn), *const zmend = zmbeg + zmsiz;
      for(const auto &dest : i.dests) {
        auto &buffer = zprn_buf[dest];
        if(buffer.empty() || (buffer.back().size() + zmsiz) > 1232) {
          // create new buffer slot
          buffer.emplace_back(zprn_hdrv);
        }
        auto &bufitem = buffer.back();
        bufitem.reserve(bufitem.size() + zmsiz);
        bufitem.insert(bufitem.end(), zmbeg, zmend);
      }
    }

    zprn_msgs.clear();

    // send ZPRN v2 messages
    for(const auto &bufpd : zprn_buf)
      for(const auto &pkt : bufpd.second)
        if(!sendto_peer(bufpd.first, pkt.data(), pkt.size()))
          got_error = true;

    zprn_buf.clear();

   flush_stdstreams:
    if(got_error) {
      fflush(stdout);
      fflush(stderr);
    }
  }
}
