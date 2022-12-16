#include <unistd.h>
#include <sys/fcntl.h>
#include <utime.h>
#include <errno.h>

#include "bank.h"

#include <string>

using namespace BankOfEuler;
using namespace std;

bool Bank::exists(const string &hdir, const string &hval) {
  if (hval == sctx->rh1) // everyone has 0
    return true;

  char fn[4096];
  snprintf(fn, sizeof(fn), "%s/%s/%s", home.c_str(), hdir.c_str(), hval.c_str());
  FILE *fp = fopen(fn, "r");
  if (!fp)
    return false;
  fclose(fp);

  return true;
}

bool Bank::create(const string &hdir, const string &hval) {
  if (hval == sctx->rh1) // everyone has 0
    return false;

  char dn[4096];
  snprintf(dn, sizeof(dn), "%s/%s", home.c_str(), hdir.c_str());
  if (::mkdir(dn, 0700) < 0)
    assert(errno == EEXIST);

  char fn[4096];
  snprintf(fn, sizeof(fn), "%s/%s", dn, hval.c_str());

  int fd = ::open(fn, O_CREAT | O_EXCL, 0);
  if (fd < 0) {
    assert(errno == EEXIST); // abort if unexpected file error
    return false;
  }
  close(fd);

  return true;
}

bool Bank::erase(const string &hdir, const string &hval) {
  if (hval == sctx->rh1) // everyone has 0
    return false;

  char fn[4096];
  snprintf(fn, sizeof(fn), "%s/%s/%s", home.c_str(), hdir.c_str(), hval.c_str());
  assert(0 == unlink(fn));

  return true;
}

bool Bank::touch(const string &hdir, const string &hval) {
  if (hval == sctx->rh1) // everyone has 0
    return true;

  char fn[4096];
  snprintf(fn, sizeof(fn), "%s/%s/%s", home.c_str(), hdir.c_str(), hval.c_str());

  time_t now = time(NULL);
  struct utimbuf buf;
  buf.actime = now;
  buf.modtime = now;
  int ret = utime(fn, &buf);

  return (ret == 0);
}

#if 0
void Bank::split(const Number &gx, const Number &ga, const Number &gb) {
  assert(gx == (ga * gb) % sctx->p);

  string hx = sctx->rehash(gx);
  string ha = sctx->rehash(ga);
  string hb = sctx->rehash(gb);

  assert(ha != hb);
  assert(ha != hx);
  assert(hb != hx);

  assert(exists(hx));
  assert(!exists(ha));
  assert(!exists(hb));

  erase(hx);
  create(ha);
  create(hb);
}

void Bank::merge(const Number &ga, const Number &gb, const Number &gx) {
  assert(gx == (ga * gb) % sctx->p);

  string ha = sctx->rehash(ga);
  string hb = sctx->rehash(gb);
  string hx = sctx->rehash(gx);

  assert(ha != hb);
  assert(ha != hx);
  assert(hb != hx);

  assert(exists(ha));
  assert(exists(hb));
  assert(!exists(hx));

  erase(ha);
  erase(hb);
  create(hx);
}
#endif

Number Bank::execute(const MergeCommand *com) {
  fprintf(stderr, "bank got merge command,");

//  fprintf(stderr, "aval = %s, ", com->aval.c_str());
//  fprintf(stderr, "bval = %s, ", com->bval.c_str());
//  fprintf(stderr, "adir = %s, ", com->adir.c_str());
//  fprintf(stderr, "bdir = %s, ", com->bdir.c_str());
//  fprintf(stderr, "cdir = %s", com->cdir.c_str());

  assert(com->adir != com->bdir || com->aval != com->bval);

  Number cval = (com->aval * com->bval) % sctx->p;

  string hadir = sctx->rehash(com->adir);
  string hbdir = sctx->rehash(com->bdir);
  string hcdir = sctx->rehash(com->cdir);
  string haval = sctx->rehash(com->aval);
  string hbval = sctx->rehash(com->bval);
  string hcval = sctx->rehash(cval);

  assert(com->aval == 1 || exists(hadir, haval));
  assert(com->bval == 1 || exists(hbdir, hbval));
  assert(cval == 1 || !exists(hcdir, hcval));

  erase(hadir, haval);
  erase(hbdir, hbval);
  create(hcdir, hcval);

  return 1;
}

Number Bank::execute(const CheckCommand *com) {
  fprintf(stderr, "bank got check command");
  fprintf(stderr, "adir = %s ", com->adir.c_str());
  fprintf(stderr, "aval = %s ", com->aval.c_str());

  string hadir = sctx->rehash(com->adir);
  string haval = sctx->rehash(com->aval);

  return exists(hadir, haval);
}

Number Bank::execute(const SplitCommand *com) {
  fprintf(stderr, "bank got split command");
  fprintf(stderr, "avalpos = %s, ", com->avalpos.gx.c_str());
  fprintf(stderr, "bvalpos = %s, ", com->bvalpos.gx.c_str());
  fprintf(stderr, "adir = %s, ", com->adir.c_str());
  fprintf(stderr, "bdir = %s, ", com->bdir.c_str());
  fprintf(stderr, "cdir = %s", com->cdir.c_str());

  assert(com->avalpos.verify(sctx));
  assert(com->bvalpos.verify(sctx));

  Number aval = com->avalpos.gx;
  Number bval = com->bvalpos.gx;
  assert(com->adir != com->bdir || aval != bval);

  Number cval = (aval * bval) % sctx->p;

  string hadir = sctx->rehash(com->adir);
  string hbdir = sctx->rehash(com->bdir);
  string hcdir = sctx->rehash(com->cdir);
  string haval = sctx->rehash(aval);
  string hbval = sctx->rehash(bval);
  string hcval = sctx->rehash(cval);

  assert(aval == 1 || !exists(hadir, haval));
  assert(bval == 1 || !exists(hbdir, hbval));
  assert(cval == 1 || exists(hcdir, hcval));

  create(hadir, haval);
  create(hbdir, hbval);
  erase(hcdir, hcval);

  return 1;
}

Number Bank::execute(const Command *com) {
  switch (com->magic) {
  default:
    assert(!"bad command magic");
  case MergeCommand::magic:
    return execute((const MergeCommand *)com);
  case CheckCommand::magic:
    return execute((const CheckCommand *)com);
  case SplitCommand::magic:
    return execute((const SplitCommand *)com);
  }
}

Number Bank::execute(const ExecuteRequest &req) {
  Command *command = req.command;
  KeytieCertificate *kcert = req.kcert;
  Number e;
  e.powmod(kcert->encrypted_e, sctx->sd, sctx->sn);
  ElGamalSecret egs(kcert->eg_public, e);

  AuthorizeCertificate *acert = req.acert;
  unsigned int n_acerts = req.n_acerts;

  command->decrypt(egs);

  assert(command->authorize(sctx, acert, n_acerts));
  return execute(command);
}
