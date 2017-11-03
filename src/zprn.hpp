#ifndef ZPRN_HPP
# define ZPRN_HPP 1
# include <inttypes.h>
# include <vector>

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

  zprn();
  bool valid() const noexcept;
  void send(const std::vector<uint32_t> &peers) const;
};
#endif
