#ifndef __COMMAND_H__
#define __COMMAND_H__ 1

#include <list>

#include "number.h"
#include "positive.h"
#include "authorize.h"
#include "elgamal.h"

namespace BankOfEuler {

struct Command {
  unsigned int magic; // not static because we are virtual

  virtual void read(FILE *fp, bool rm = 1) = 0;
  virtual void write(FILE *fp) const = 0;
  virtual void hash_update(CTX *ctx, Number &hash) const = 0;
  virtual void decrypt(const ElGamalSecret &) = 0;
  virtual void encrypt(const ElGamalPublic &) = 0;
  virtual bool authorize(CTX *ctx, const AuthorizeCertificate *acert, unsigned int n) = 0;
};

extern Command *read_command(FILE *fp);

struct MergeCommand : Command {
  const static unsigned int magic = 0x71346EC;

  Number adir, bdir, cdir;
  Number aval, bval;

  MergeCommand() {
    Command::magic = magic;
  }
  virtual ~MergeCommand() { }

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    adir.read(fp);
    bdir.read(fp);
    cdir.read(fp);
    aval.read(fp);
    bval.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    adir.write(fp);
    bdir.write(fp);
    cdir.write(fp);
    aval.write(fp);
    bval.write(fp);
  }

  void hash_update(CTX *ctx, Number &hash) const {
    ctx->hash_update(hash, magic);
    ctx->hash_update(hash, adir);
    ctx->hash_update(hash, bdir);
    ctx->hash_update(hash, cdir);
    ctx->hash_update(hash, aval);
    ctx->hash_update(hash, bval);
  }

  void decrypt(const ElGamalSecret &egs) {
    egs.decrypt(adir);
    egs.decrypt(bdir);
    egs.decrypt(cdir);
    egs.decrypt(aval);
    egs.decrypt(bval);
  }

  void encrypt(const ElGamalPublic &egp) {
    egp.encrypt(adir);
    egp.encrypt(bdir);
    egp.encrypt(cdir);
    egp.encrypt(aval);
    egp.encrypt(bval);
  }

  bool authorize(CTX *ctx, const AuthorizeCertificate *acert, unsigned int n);
};

struct CheckCommand : Command {
  const static unsigned int magic = 0x71CC6EC;

  Number adir;
  Number aval;

  CheckCommand() {
    Command::magic = magic;
  }
  virtual ~CheckCommand() { }

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    adir.read(fp);
    aval.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    adir.write(fp);
    aval.write(fp);
  }

  void hash_update(CTX *ctx, Number &hash) const {
    ctx->hash_update(hash, magic);
    ctx->hash_update(hash, adir);
    ctx->hash_update(hash, aval);
  }

  void decrypt(const ElGamalSecret &egs) {
    egs.decrypt(adir);
    egs.decrypt(aval);
  }

  void encrypt(const ElGamalPublic &egp) {
    egp.encrypt(adir);
    egp.encrypt(aval);
  }

  bool authorize(CTX *ctx, const AuthorizeCertificate *acert, unsigned int n);
};

struct SplitCommand : Command {
  const static unsigned int magic = 0x57717C0;

  Number adir, bdir, cdir;
  PositiveProof avalpos, bvalpos;

  SplitCommand() {
    Command::magic = magic;
  }
  virtual ~SplitCommand() { }

  void read(FILE *fp, bool rm = 1) {
    if (rm) assert(magic == read_int32(fp));
    adir.read(fp);
    bdir.read(fp);
    cdir.read(fp);
    avalpos.read(fp);
    bvalpos.read(fp);
  }

  void write(FILE *fp) const {
    write_int32(magic, fp);
    adir.write(fp);
    bdir.write(fp);
    cdir.write(fp);
    avalpos.write(fp);
    bvalpos.write(fp);
  }

  void hash_update(CTX *ctx, Number &hash) const {
    ctx->hash_update(hash, magic);
    ctx->hash_update(hash, adir);
    ctx->hash_update(hash, bdir);
    ctx->hash_update(hash, cdir);
    ctx->hash_update(hash, avalpos.h, ctx->hn);
    ctx->hash_update(hash, bvalpos.h, ctx->hn);
  }

  void decrypt(const ElGamalSecret &egs) {
    egs.decrypt(adir);
    egs.decrypt(bdir);
    egs.decrypt(cdir);
    egs.decrypt(avalpos.gx);
    egs.decrypt(bvalpos.gx);
  }

  void encrypt(const ElGamalPublic &egp) {
    egp.encrypt(adir);
    egp.encrypt(bdir);
    egp.encrypt(cdir);
    egp.encrypt(avalpos.gx);
    egp.encrypt(bvalpos.gx);
  }

  bool authorize(CTX *ctx, const AuthorizeCertificate *acert, unsigned int n);
};

}

#endif
