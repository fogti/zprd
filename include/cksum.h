#ifndef CKSUM_H
# define CKSUM_H 1
# include <inttypes.h>
# ifdef __cplusplus
extern "C" {
# endif
  uint16_t in_cksum(const uint16_t *ptr, int nbytes);
  uint64_t in_hashsum(const uint8_t *ptr, uint16_t nbytes);
# ifdef __cplusplus
}
template<typename T>
uint16_t IN_CKSUM(const T *const ptr) noexcept {
  return in_cksum(reinterpret_cast<const uint16_t*>(ptr), sizeof(T));
}
# endif
#endif
