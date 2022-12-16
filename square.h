#ifndef __SQUARE_H__
#define __SQUARE_H__ 1

#include "number.h"
#include "ctx.h"

namespace BankOfEuler {

// we want to prove that log(gx)^2 = log(gx2)

struct SquareRequest {
  const static unsigned int magic;

  Number gx, gx2;
  unsigned int n;

  void generate(CTX *ctx, const Number &x);
  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    gx2.read(fp);
    n = read_int32(fp);
  }

  void write(FILE *fp) const {
     write_int32(magic, fp);
     gx.write(fp);
     gx2.write(fp);
     write_int32(n, fp);
  }
};


// ... so here are some commitments gy_i, which are each either g^y_i or gx^y_i, chosen
// at random.  the expected response is either (g^y_i)^x = gx^y_i, or (gx^y_i)^x = gx2^y_i.
// this is encoded into the signed hash h.

struct SquareChallenge {
  const static unsigned int magic;

  Number gx, gx2;
  NumberVector gy;
  time_t t;
  Number h, sh;

  void generate(SCTX *sctx, const SquareRequest &);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    gx2.read(fp);
    gy.read(fp);
    t = read_int32(fp);
    h.read(fp);
    sh.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    gx.write(fp);
    gx2.write(fp);
    gy.write(fp);
    write_int32(t, fp);
    h.write(fp);
    sh.write(fp);
  }
};


// gyx_i = gy_i^x
// this will verify h.

struct SquareResponse {
  const static unsigned int magic;

  Number gx, gx2;
  time_t t;
  Number h, sh;
  NumberVector gyx;

  void generate(CTX *ctx, const SquareChallenge &, const Number &);
  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    gx2.read(fp);
    t = read_int32(fp);
    h.read(fp);
    sh.read(fp);
    gyx.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    gx.write(fp);
    gx2.write(fp);
    write_int32(t, fp);
    h.write(fp);
    sh.write(fp);
    gyx.write(fp);
  }
};


// this proves that log(gx)^2 = log(gx2), else with probability 2^-n.

struct SquareProof {
  const static unsigned int magic;

  Number gx, gx2;
  unsigned int n;
  Number h, sh;

  void generate(SCTX *sctx, const SquareResponse &);
  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    gx2.read(fp);
    n = read_int32(fp);
    h.read(fp);
    sh.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    gx.write(fp);
    gx2.write(fp);
    write_int32(n, fp);
    h.write(fp);
    sh.write(fp);
  }
};

}

#endif
