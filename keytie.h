#ifndef __KEYTIE_H__
#define __KEYTIE_H__ 1

#include "assert.h"
#include "number.h"
#include "elgamal.h"
#include "small.h"
#include "square.h"
#include "command.h"

namespace BankOfEuler {

struct KeytieRequest {
  const static unsigned int magic = 0xC317131;

  Number cmd_hash;
  ElGamalSecret eg_secret;

  void generate(CTX *ctx, const ElGamalSecret &eg_secret, const Command *command) {
    this->eg_secret = eg_secret;
    ctx->hash_init(cmd_hash);
    command->hash_update(ctx, cmd_hash);
    ctx->hash_final(cmd_hash);
  }

  void generate(CTX *ctx, const ElGamalSecret &eg_secret, const Number &cmd_hash) {
    this->eg_secret = eg_secret;
    this->cmd_hash = cmd_hash;
  }

  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    cmd_hash.read(fp);
    eg_secret.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    cmd_hash.write(fp);
    eg_secret.write(fp);
  }
};


struct KeytieCertificate {
  const static unsigned int magic = 0xC317133;

  Number cmd_hash;
  ElGamalPublic eg_public;
  Number encrypted_e;
  time_t expires;

  Number h, sh; // hash and signature of certificate

  void generate(SCTX *ctx, const KeytieRequest &req);
  bool verify(CTX *ctx);

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    cmd_hash.read(fp);
    eg_public.read(fp);
    encrypted_e.read(fp);
    expires = read_int32(fp);
    h.read(fp);
    sh.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    cmd_hash.write(fp);
    eg_public.write(fp);
    encrypted_e.write(fp);
    write_int32(expires, fp);
    h.write(fp);
    sh.write(fp);
  }
};

}

#endif
