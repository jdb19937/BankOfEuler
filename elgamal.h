#ifndef __ELGAMAL_H__
#define __ELGAMAL_H__ 1

#include "ctx.h"
#include "number.h"

namespace BankOfEuler {

// this class implements elgamal encryption, described at:
// http://en.wikipedia.org/wiki/ElGamal_encryption
//
// encrypted values are encoded as a single number under n^2
// rather than a pair.  encryption is identity when r = 0, and
// decryption is identity whenever r < n.

struct ElGamalPublic {
  const static unsigned int magic = 0x3164747;

  Number g;
  Number ge;
  Number n;

  ElGamalPublic() { }

  ElGamalPublic(const ElGamalPublic &eg) {
    *this = eg;
  }

  ElGamalPublic &operator =(const ElGamalPublic &eg) {
    g = eg.g;
    ge = eg.ge;
    n = eg.n;
  }

  void encrypt(Number &x, const Number &r) const {
    Number n2 = n * n;
    assert(x < n2);

    Number gr;
    gr.powmod(g, r, n);
    if (x >= n) {
      Number gr2 = 1 + Number(x / n);
      gr *= gr2;
      gr %= n;
    }

    Number xger;
    xger.powmod(ge, r, n);
    xger *= x;
    xger %= n;

    x = ((gr - 1) * n + xger);
  }

  Number encrypt(Number &x) const {
    Number r;
    r.urandomm(n);
    encrypt(x, r);
    return r;
  }

  void decrypt(Number &y, const Number &r) const {
    encrypt(y, -r);
  }

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    g.read(fp);
    ge.read(fp);
    n.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    g.write(fp);
    ge.write(fp);
    n.write(fp);
  }

  void hash_update(CTX *ctx, Number &hash) {
    assert(n < ctx->hn);
    ctx->hash_update(hash, magic);
    ctx->hash_update(hash, g, n);
    ctx->hash_update(hash, ge, n);
    ctx->hash_update(hash, n, ctx->hn);
  }

  bool operator == (const ElGamalPublic &egp) {
    return (g == egp.g && ge == egp.ge && n == egp.n);
  }
};


struct ElGamalSecret : ElGamalPublic {
  const static unsigned int magic = 0x3164749;

  Number e;

  ElGamalSecret() { }

  ElGamalSecret(const Number &g, const Number &e, const Number &n) {
    this->g = g;
    this->e = e;
    this->n = n;
    this->ge.powmod(g, e, n);
  }

  ElGamalSecret(const ElGamalPublic &egp, const Number &e) : ElGamalPublic(egp) {
    this->e = e;
  }

  ElGamalSecret(const ElGamalSecret &egs) {
    *this = egs;
  }

  ElGamalSecret &operator =(const ElGamalSecret &egs) {
    g = egs.g;
    ge = egs.ge;
    n = egs.n;
    e = egs.e;
  }

  void generate(const Number &n);

  void decrypt(Number &y) const {
    Number n2 = n * n;
    assert(y < n2);

    if (y < n)
      return;

    Number gr = 1 + Number(y / n);
    Number gre;
    gre.powmod(gr, -e, n);

    Number xgre = y % n;

    y = ((gre * xgre) % n);
  }

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    ElGamalPublic::read(fp, 1);
    e.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    ElGamalPublic::write(fp);
    e.write(fp);
  }

  void hash_update(CTX *ctx, Number &hash) {
    ctx->hash_update(hash, magic);
    ElGamalPublic::hash_update(ctx, hash);
    ctx->hash_update(hash, e, n);
  }

  bool operator == (const ElGamalSecret &egs) {
    return (g == egs.g && ge == egs.ge && n == egs.n && e == egs.e);
  }
};

}

#endif
