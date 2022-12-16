#ifndef __CTX_H__
#define __CTX_H__ 1

#include "number.h"

namespace BankOfEuler {

struct CTX {
  CTX(const char *home = NULL);
  virtual ~CTX() { }

  std::string home;

  Number g, p, p1, q, k, hg, hn, sn, se, v;
  unsigned int rounds;

  std::string rh1;

  virtual void hash_init(Number &h) {
    h = 1;
  }

  virtual void hash_update(Number &h, unsigned int x) {
    Number hx;
    Number t32 = 1;
    t32 <<= 32;
    h.powmod(h, t32, hn);
    hx.powmod(hg, x, hn);

    h *= hx;
    h %= hn;
  }

  virtual void hash_update(Number &h, const Number &x, const Number &max_x) {
    Number hx;
    h.powmod(h, max_x, hn);
    hx.powmod(hg, x, hn);
    h *= hx;
    h %= hn;
  }

  virtual void hash_update(Number &h, const Number &x) { // by default, max_x = p
    Number hx;
    h.powmod(h, p, hn);
    hx.powmod(hg, x, hn);
    h *= hx;
    h %= hn;
  }

  virtual void hash_final(Number &h) {

  }

  void penc(Number &gx, const Number &x) {
    gx.powmod(g, x, p);
  }

  std::string rehash(const Number &);
};

struct SCTX : CTX {
  SCTX(const char *home = NULL);
  virtual ~SCTX() { }

  Number hp, hq, hl, sd;
  time_t expiry;

  virtual void hash_init(Number &h) {
    h = 0;
  }

  virtual void hash_update(Number &h, unsigned int x) {
    h <<= 32;
    h += x;
    h %= hl;
  }

  virtual void hash_update(Number &h, const Number &x, const Number &max_x) {
    h *= max_x;
    h += x;
    h %= hl;
  }

  virtual void hash_update(Number &h, const Number &x) { // by default, max_x = p
    h *= p;
    h += x;
    h %= hl;
  }

  virtual void hash_final(Number &h) {
    h.powmod(hg, h, hn);
  }
};

}

#endif
