/**
 * remote_peer.hpp
 * This file contains parts of the oAFa 'outer address family abstraction'
 * (C) 2018 Erik Zscheile.
 * License: GPL-2+
 **/
#pragma once
#include <sys/socket.h> // sockaddr_storage
#include <stddef.h>     // size_t
#include <time.h>       // time_t

#include <memory>
#include <shared_mutex>
#include <string>

class remote_peer_t : public std::enable_shared_from_this<remote_peer_t> {
 protected:
  typedef std::shared_mutex _mtx_t;
  mutable _mtx_t _mtx;
 public:
  struct sockaddr_storage saddr;

  remote_peer_t() noexcept;
  virtual ~remote_peer_t() = default;
  remote_peer_t(const struct sockaddr_storage &sas) noexcept;
  remote_peer_t(remote_peer_t &&o) noexcept;
  remote_peer_t(const remote_peer_t &o) noexcept = delete;

  // convert saddr to a string
  auto addr2string() const -> std::string;

  // generic access methods, locked
  auto get_saddr() const noexcept -> sockaddr_storage;
  void set_saddr(const sockaddr_storage &sas, bool do_lock = true) noexcept;
  // set2catchall sets saddr (unlocked) to the use-all-interfaces-catchall address
  //  used by main.cxx:setup_server_fd
  bool set2catchall() noexcept;
  void set_port(uint16_t port, bool do_lock = true) noexcept;
  void set_port_if_unset(uint16_t port, bool do_lock = true) noexcept;

  // NOTE: eventually, check if try{ shared_from_this()->unique() } catch { true },
  //       and omit lock in that case (but this could create some race conditions in rare cases)
  template<typename Fn>
  auto locked_crun(const Fn &fn) const {
    std::shared_lock<_mtx_t> lock(_mtx);
    return fn(*this);
  }
  template<typename Fn>
  auto locked_run(const Fn &fn) {
    std::unique_lock<_mtx_t> lock(_mtx);
    return fn(*this);
  }
};

typedef std::shared_ptr<remote_peer_t> remote_peer_ptr_t;
bool operator==(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept;
bool operator!=(const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept;
bool operator< (const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept;
bool operator> (const remote_peer_t &lhs, const remote_peer_t &rhs) noexcept;

struct remote_peer_detail_t : remote_peer_t {
  time_t seen;
  size_t cent; // config entry
  bool to_discard; // should this entry be deleted in the next cleanup round?

  remote_peer_detail_t() noexcept;
  explicit remote_peer_detail_t(const sockaddr_storage &sas) noexcept;
  explicit remote_peer_detail_t(const remote_peer_t &o) noexcept;
  explicit remote_peer_detail_t(remote_peer_t &&o) noexcept;
  remote_peer_detail_t(const remote_peer_detail_t &o) noexcept = delete;
  remote_peer_detail_t(const remote_peer_t &o, const size_t cfgent) noexcept;
  remote_peer_detail_t(remote_peer_t &&o, const size_t cfgent) noexcept;

  const char *cfgent_name() const noexcept;

  template<typename Fn>
  auto locked_crun(const Fn &fn) const {
    std::shared_lock<_mtx_t> lock(_mtx);
    return fn(*this);
  }
  template<typename Fn>
  auto locked_run(const Fn &fn) {
    std::unique_lock<_mtx_t> lock(_mtx);
    return fn(*this);
  }
};

typedef std::shared_ptr<remote_peer_detail_t> remote_peer_detail_ptr_t;
