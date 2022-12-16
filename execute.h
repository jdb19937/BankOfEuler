#ifndef __EXECUTE_H__
#define __EXECUTE_H__ 1

#include "assert.h"
#include "number.h"
#include "small.h"
#include "square.h"
#include "elgamal.h"
#include "command.h"
#include "keytie.h"

namespace BankOfEuler {

struct ExecuteRequest {
  const static unsigned int magic = 0x3C8873;
  const static unsigned int max_acerts = 64;

  Command *command;
  KeytieCertificate *kcert;

  unsigned int n_acerts;
  AuthorizeCertificate *acert;

  bool _do_free;

  ExecuteRequest() {
    command = NULL;
    acert = NULL;
    kcert = NULL;
    n_acerts = 0;
    _do_free = 0;
  }

  ~ExecuteRequest() {
    if (_do_free) {
      if (command)
        delete command;
      if (kcert)
        delete kcert;
      if (acert)
        delete[] acert;
    }
  }

  void generate(
    CTX *ctx,
    Command *command,
    KeytieCertificate *kcert,
    AuthorizeCertificate *acert, unsigned int n_acerts
  );

  bool verify(CTX *ctx) const;

  void read(FILE *fp, bool rm = 1);
  void write(FILE *fp) const;
};

struct ExecuteCertificate {
  const static unsigned int magic = 0x3C99923;

  Number cmd_hash;
  Number ktc_hash;
  Number result;
  time_t t;

  Number h, sh;

  void generate(SCTX *sctx, const Number &cmd_hash, const ExecuteRequest &req, const Number &result);
  bool verify(CTX *ctx) const;

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    cmd_hash.read(fp);
    ktc_hash.read(fp);
    result.read(fp);
    t = read_int32(fp);
    h.read(fp);
    sh.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    cmd_hash.write(fp);
    ktc_hash.write(fp);
    result.write(fp);
    write_int32(t, fp);
    h.write(fp);
    sh.write(fp);
  }
};

}

#endif
