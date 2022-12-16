#include "ctx.h"

using namespace BankOfEuler;

CTX::CTX(const char *_home) {
  if (!_home)
    if (!(_home = getenv("BANKOFEULER_HOME")))
      _home = "/usr/local/BankOfEuler";
  this->home = _home;

  std::string sdir = std::string("file:") + home + std::string("/params/");

  g = sdir + "g";
  p = sdir + "p";
  assert(g.is_qr(p));

  p1 = p - 1;
  q = p1 / 2;
  k = sqrt(q / 2) - 1;

  {
    Number gq;
    gq.powmod(g, q, p);
    assert(gq == 1);
  }

  hg = sdir + "hg";
  hn = sdir + "hn";

  sn = sdir + "sn";
  se = sdir + "se";

  {
    Number p2, p4;
    mpz_sqrt(p2.get_mpz_t(), p.get_mpz_t());
    mpz_sqrt(p4.get_mpz_t(), p2.get_mpz_t());
    Number::v = p2 * p4;
  }

  Number nrounds = sdir + "rounds";
  rounds = nrounds.get_ui();

  rh1 = rehash(1);
}

SCTX::SCTX(const char *_home) : CTX(_home) {
  std::string sdir = std::string("file:") + this->home + std::string("/sparams/");

  hp = sdir + "hp";
  hq = sdir + "hq";

  hl = (hp - 1) * (hq - 1) / 4;
  {
    Number t;
    t.powmod(hg, hl, hn);
    assert(t == 1);
  }

  sd = sdir + "sd";

  Number nexpiry = sdir + "expiry";
  expiry = nexpiry.get_si();
}

std::string CTX::rehash(const Number &x) {
  Number h;
  h.powmod(hg, x, hn);

  Number t256 = 1;
  t256 <<= 256;

  Number rh = 0;
  while (h > 0) {
    Number z = h;
    z %= t256;
    rh ^= z;
    h >>= 256;
  }

  char buf[4096], *p = buf + 2048;
  mpz_get_str(p, 16, rh.get_mpz_t());
  int plen = strlen(p);
  while (plen < 64) {
    plen++;
    *--p = '0';
  }
  *--p = 'H';

  return std::string(p);
}

