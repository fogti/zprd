#ifndef ZPRN_HPP
# define ZPRN_HPP 1
# include <inttypes.h>
# include <vector>

struct zprn {
  uint8_t zprn_mgc;
  uint8_t zprn_ver;

  /* zprn_cmd = command
   *
   * values:
   *    0 = route modification
   */
  uint8_t zprn_cmd;

  /* zprn_prio = priority
   *
   * encoding:
   *    0   use first
   *  255   worst / invalid / delete
   *  else  fallback
   *
   * using equivalent:
   *  cmd   meaning
   *    0   hop count
   */
  uint8_t zprn_prio;

  union {
    struct {
      uint32_t dsta;
    } route;
  } zprn_un;

  zprn();
  bool valid() const noexcept;
  void send(const std::vector<uint32_t> &peers) const;
};
#endif
