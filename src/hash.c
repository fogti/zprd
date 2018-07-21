/** zprd hash.c
    (C) 2018 Erik Zscheile
    License: MIT
 **/
#include <stdint.h>

void zs_hash_combine(uintmax_t *seed, const uintmax_t o) {
  // source of rndst : https://stackoverflow.com/questions/5889238/why-is-xor-the-default-way-to-combine-hashes#comment54810251_27952689
  // rndst := inverse of golden ratio as a ... fixed point fraction
  // the following uses more entropy on 64bit (e.g. when available)
  const uintmax_t sedc = *seed;
  const uintmax_t rndst =
    (sizeof(uintmax_t) >= 8) ? 0x9e3779b97f4a7c15 : 0x9e3779b9;
  *seed ^= rndst + o + (sedc << 6) + (sedc >> 2);
}
