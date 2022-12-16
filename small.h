#ifndef __SMALL_H__
#define __SMALL_H__ 1

#include "assert.h"
#include "number.h"
#include "ctx.h"

namespace BankOfEuler {

// these are some random numbers between 1 and k.

struct SmallNonce {
  NumberVector y;
};


// this is our request for a proof that x is a small number.
// it contains a commitment to x, and commitments to the nonce.

struct SmallRequest {
  const static unsigned int magic;

  Number gx;
  NumberVector gy;

  void generate(CTX *ctx, const Number &, SmallNonce *);
  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    gy.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    gx.write(fp);
    gy.write(fp);
  }
};


// the challenge contains a number c.  the i'th bit of c says whether
// we want y_i or y_i + x for each element of the nonce.

struct SmallChallenge {
  const static unsigned int magic;

  Number gx;
  time_t t;
  Number c;
  Number h, sh;

  void generate(SCTX *sctx, const SmallRequest &);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    t = read_int32(fp);
    c.read(fp);
    h.read(fp);
    sh.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    gx.write(fp);
    write_int32(t, fp);
    c.write(fp);
    h.write(fp);
    sh.write(fp);
  }
};


// the i'th element of yx is either y_i or y_i + x, depending on the i'th bit of c.
// this says nothing about x because each y_i is much larger than x.  the server
// will verify that 0 < yx_i < k.

struct SmallResponse {
  const static unsigned int magic;

  Number gx;
  time_t t;
  Number h, sh;
  NumberVector yx;

  void generate(CTX *ctx, const SmallChallenge &, const Number &x, const SmallNonce *nonce);
  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    t = read_int32(fp);
    h.read(fp);
    sh.read(fp);
    yx.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    gx.write(fp);
    write_int32(t, fp);
    h.write(fp);
    sh.write(fp);
    yx.write(fp);
  }
};


// this proves that -k < x < k, else with probability 2^-n.

struct SmallProof {
  const static unsigned int magic;

  Number gx;
  time_t t;
  Number h, sh;
  unsigned int n;

  void generate(SCTX *sctx, const SmallResponse &);
  bool verify(CTX *ctx);

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
