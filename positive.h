#ifndef __POSITIVE_H__
#define __POSITIVE_H__ 1

#include "assert.h"
#include "number.h"
#include "small.h"
#include "square.h"

namespace BankOfEuler {

struct PositiveNonce {
  SmallNonce anonce;
  SmallNonce bnonce;
};


// we want to prove that x is positive modulo p, that is, 0 <= x < p1/2.
//
// (define k = sqrt(p1/2) - 1)
//
// instead we will just show that -k < x < k^2 + k < p1/2, which is good
// enough because -k is worthless.
//
// to do this, decompose x = a^2 + b, with b < a, and reveal
// g^a, g^(a^2) and g^b.  now prove log(g^(a^2)) = log(g^a)^2,
// -k < log(g^a) < k, and -k < log(g^b) < k.

struct PositiveRequest {
  const static unsigned int magic = 0x9A;

  SmallRequest areq;
  SmallRequest breq;
  SquareRequest a2req;

  void generate(CTX *ctx, const Number &x, PositiveNonce *nonce);

  // don't compute a and b again if we don't have to
  void generate(CTX *ctx, const Number &x, PositiveNonce *nonce,
    const Number &a, const Number &b);
  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    areq.read(fp);
    breq.read(fp);
    a2req.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    areq.write(fp);
    breq.write(fp);
    a2req.write(fp);
  }
};

struct PositiveChallenge {
  const static unsigned int magic = 0x9B;

  SmallChallenge achal;
  SmallChallenge bchal;
  SquareChallenge a2chal;

  void generate(SCTX *sctx, const PositiveRequest &);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    achal.read(fp);
    bchal.read(fp);
    a2chal.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    achal.write(fp);
    bchal.write(fp);
    a2chal.write(fp);
  }
};

struct PositiveResponse {
  const static unsigned int magic = 0x9C;

  SmallResponse aresp;
  SmallResponse bresp;
  SquareResponse a2resp;

  void generate(CTX *ctx, const PositiveChallenge &, const Number &x, const PositiveNonce *nonce);

  // don't compute a and b again if we don't have to
  void generate(CTX *ctx, const PositiveChallenge &, const Number &x,
    const PositiveNonce *nonce,
    const Number &a, const Number &b);

  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    aresp.read(fp);
    bresp.read(fp);
    a2resp.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    aresp.write(fp);
    bresp.write(fp);
    a2resp.write(fp);
  }
};


// this proves 0 <= x < p1/2, else with probability 3*(2^-n)

struct PositiveProof {
  const static unsigned int magic = 0x9D;

  Number gx;
  time_t t;
  Number h, sh;
  unsigned int n;

  void generate(SCTX *sctx, const PositiveResponse &);
  bool verify(CTX *ctx) const;

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    t = read_int32(fp);
    h.read(fp);
    sh.read(fp);
    n = read_int32(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    gx.write(fp);
    write_int32(t, fp);
    h.write(fp);
    sh.write(fp);
    write_int32(n, fp);
  }
};

}

#endif
