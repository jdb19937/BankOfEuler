#ifndef __AUTHORIZE_H__
#define __AUTHORIZE_H__ 1

#include "assert.h"
#include "number.h"
#include "ctx.h"

namespace BankOfEuler {

struct AuthorizeNonce {
  Number r;
};

// this is the Schnorr protocol described in:
// http://en.wikipedia.org/wiki/Proof_of_knowledge
//
// it is augmented by a signed hash to make the protocol statelesss.

struct AuthorizeRequest {
  const static unsigned int magic = 0xA6667;

  Number gx;
  Number gr;
  Number ktc_hash;

  void generate(CTX *ctx,
    const Number &x, const Number &ktc_hash,
    AuthorizeNonce *nonce);
  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    gr.read(fp);
    ktc_hash.read(fp);
  }

  void write(FILE *fp, bool wm = 1) const {
    if (wm) write_int32(magic, fp);
    gx.write(fp);
    gr.write(fp);
    ktc_hash.write(fp);
  }
};

struct AuthorizeChallenge {
  const static unsigned int magic = 0xA7778;

  Number c;
  time_t t;
  Number h, sh;

  void generate(SCTX *sctx, const AuthorizeRequest &);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    c.read(fp);
    t = read_int32(fp);
    h.read(fp);
    sh.read(fp);
  }

  void write(FILE *fp, bool wm = 1) const {
    if (wm) write_int32(magic, fp);
    c.write(fp);
    write_int32(t, fp);
    h.write(fp);
    sh.write(fp);
  }
};

struct AuthorizeResponse {
  const static unsigned int magic = 0xA8889;

  Number gx;
  Number gr;
  Number c;
  time_t t;
  Number h, sh;
  Number cxr;
  Number ktc_hash;

  void generate(CTX *ctx,
    const AuthorizeChallenge &, const Number &x,
    const Number &ktc_hash,
    const AuthorizeNonce *nonce
  );
  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    gr.read(fp);
    c.read(fp);
    t = read_int32(fp);
    h.read(fp);
    sh.read(fp);
    cxr.read(fp);
    ktc_hash.read(fp);
  }

  void write(FILE *fp, bool wm = 1) const {
    if (wm) write_int32(magic, fp);
    gx.write(fp);
    gr.write(fp);
    c.write(fp);
    write_int32(t, fp);
    h.write(fp);
    sh.write(fp);
    cxr.write(fp);
    ktc_hash.write(fp);
  }
};

struct AuthorizeCertificate {
  const static unsigned int magic = 0xA888B;

  Number gx;
  time_t t;
  Number ktc_hash;
  Number h, sh;

  void generate(SCTX *sctx, const AuthorizeResponse &);
  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    gx.read(fp);
    t = read_int32(fp);
    ktc_hash.read(fp);
    h.read(fp);
    sh.read(fp);
  }

  void write(FILE *fp, bool wm = 1) const {
    if (wm) write_int32(magic, fp);
    gx.write(fp);
    write_int32(t, fp);
    ktc_hash.write(fp);
    h.write(fp);
    sh.write(fp);
  }
};

}

#endif
