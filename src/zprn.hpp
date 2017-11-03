#ifndef ZPRN_HPP
# define ZPRN_HPP 1
# include <inttypes.h>
# include <set>

struct zprn {
  uint8_t zprn_mgc;
  uint8_t zprn_ver;
  uint8_t zprn_cmd;

  union {
    struct {
      uint8_t  hops;
      uint32_t dsta;
    } route;
  } zprn_un;

  void init();
  bool valid() const noexcept;
  void send(const std::set<uint32_t> &peers) const;
};
#endif
