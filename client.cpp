#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>

#include "client.h"

using namespace BankOfEuler;

ClientBase::ClientBase(CTX *ctx) {
  this->ctx = ctx;
  in = out = NULL;
  pid = -1;
}

Client::Client(CTX *ctx) : ClientBase(ctx) {
  uid_t uid = geteuid();
  assert(uid != -1);
  struct passwd *pwd;
  assert(pwd = getpwuid(uid));

  std::string username = pwd->pw_name;
  std::string adir = ctx->home + std::string("/accounts/") + username;

  mkdir(adir.c_str(), 0700);
  account = new Account(ctx, adir.c_str());
}

ClientBase::~ClientBase() {
  disconnect();
}

Client::~Client() {
  delete account;
}

void ClientBase::connect(const char *sconf) {
  disconnect();

  int rp[2], wp[2];
  assert(0 == pipe(rp));
  assert(0 == pipe(wp));

  if (pid = fork()) {
    assert(in = fdopen(rp[0], "r"));
    assert(out = fdopen(wp[1], "w"));
    setbuf(out, NULL);
    close(rp[1]);
    close(wp[0]);
    return;
  }

  close(0);
  close(1);
  close(rp[0]);
  close(wp[1]);
  dup2(wp[0], 0);
  dup2(rp[1], 1);
  close(wp[0]);
  close(rp[1]);

  // close(2); // close stunnel stderr

  std::string conf = ctx->home + std::string("/") + sconf;
  execlp("stunnel", "stunnel", conf.c_str(), NULL);
  assert(!"exec failed");
}

void ClientBase::disconnect() {
  if (in) {
    fclose(in);
    in = NULL;
  }
  if (out) {
    fclose(out);
    out = NULL;
  }
  if (pid > 0) {
    kill(pid, 9);
    waitpid(pid, NULL, 0);
    pid = -1;
  }
}

void Client::prove_positive(const Number &x, PositiveProof *proof) {
  fprintf(stderr, "proving %s > 0\n", x.c_str());

  Number a, b;
  mpz_sqrtrem(a.get_mpz_t(), b.get_mpz_t(), x.get_mpz_t());

  PositiveNonce nonce;
  PositiveRequest req;
  req.generate(ctx, x, &nonce);
  req.write(out);

  PositiveChallenge chal;
  chal.read(in);

  PositiveResponse resp;
  resp.generate(ctx, chal, x, &nonce, a, b);

  resp.write(out);
  proof->read(in);

  assert(proof->verify(ctx));

  Number gx;
  gx.powmod(ctx->g, x, ctx->p);
  assert(proof->gx == gx);
}

void Client::authorize(const Number &folder, const KeytieCertificate &kcert, AuthorizeCertificate *acert) {
  fprintf(stderr, "authorizing %s\n", folder.c_str());

  AuthorizeNonce nonce;
  AuthorizeRequest req;
  req.generate(ctx, folder, kcert.h, &nonce);
  req.write(out);

  AuthorizeChallenge chal;
  chal.read(in);

  AuthorizeResponse resp;
  resp.generate(ctx, chal, folder, kcert.h, &nonce);

  resp.write(out);
  acert->read(in);

  assert(acert->verify(ctx));

  Number gx;
  gx.powmod(ctx->g, folder, ctx->p);
  assert(acert->gx == gx);
}

void Client::keytie(const ElGamalSecret &egs, const Command *command, KeytieCertificate *cert) {
  fprintf(stderr, "authorizing key %s\n", egs.ge.c_str());
//  fprintf(stderr, "%s, ", egs.p.c_str());
//  fprintf(stderr, "cmd_hash %s\n", cmd_hash.c_str());

  KeytieRequest req;
  req.generate(ctx, egs, command);
  req.write(out);

  cert->read(in);

  assert(cert->cmd_hash == req.cmd_hash);
  assert(cert->eg_public == egs);

  Number encrypted_e;
  encrypted_e.powmod(egs.e, ctx->se, ctx->sn);
  assert(cert->encrypted_e == encrypted_e);

  assert(cert->verify(ctx));
}

void Client::execute(
  Command *command, KeytieCertificate *kcert,
  AuthorizeCertificate *acert, unsigned int n_acerts,
  ExecuteCertificate *ecert
) {
  fprintf(stderr, "executing command\n");

  ExecuteRequest req;
  req.generate(ctx, command, kcert, acert, n_acerts);
  req.write(out);

  ecert->read(in);

  Number cmd_hash;
  ctx->hash_init(cmd_hash);
  command->hash_update(ctx, cmd_hash);
  ctx->hash_final(cmd_hash);

  assert(ecert->cmd_hash == cmd_hash);
  assert(ecert->verify(ctx));
}

void Client::merge(const Number &f, const Number &a, const Number &b) {
  Number c = a + b;

  Number ga;
  ga.powmod(ctx->g, a, ctx->p);

  Number gf;
  gf.powmod(ctx->g, f, ctx->p);

  Number gb;
  gb.powmod(ctx->g, b, ctx->p);

  MergeCommand com;
  com.adir = gf; com.bdir = gf; com.cdir = gf;
  com.aval = ga; com.bval = gb;

  ElGamalSecret egs;
  egs.generate(ctx->p);
  com.encrypt(egs);

  KeytieCertificate kc;
  keytie(egs, &com, &kc);

  AuthorizeCertificate acert[1];
  authorize(f, kc, acert);
  unsigned int n_acerts = 1;

  account->create(f, c);

  ExecuteCertificate ec;
  execute(&com, &kc, acert, 1, &ec);

  account->erase(f, a);
  account->erase(f, b);
}


void Client::merge(
  const Number &fa, const Number &a,
  const Number &fb, const Number &b,
  const Number &fc
) {
  Number c = a + b;

  Number ga;  ctx->penc(ga, a);
  Number gfa; ctx->penc(gfa, fa);
  Number gb;  ctx->penc(gb, b);
  Number gfb; ctx->penc(gfb, fb);
  Number gfc; ctx->penc(gfc, fc);

  MergeCommand com;
  com.adir = gfa; com.bdir = gfb; com.cdir = gfc;
  com.aval = ga;  com.bval = gb;

  ElGamalSecret egs;
  egs.generate(ctx->p);
  com.encrypt(egs);

  KeytieCertificate kc;
  keytie(egs, &com, &kc);

  AuthorizeCertificate acert[3];
  unsigned int n_acerts = 1;
  authorize(fa, kc, acert + 0);
  if (fa != fb)
    authorize(fb, kc, acert + n_acerts++);
  if (fa != fc && fb != fc)
    authorize(fc, kc, acert + n_acerts++);

  account->create(fc, c);

  ExecuteCertificate ec;
  execute(&com, &kc, acert, n_acerts, &ec);

  account->erase(fa, a);
  account->erase(fb, b);
}

void Client::split(
  const Number &fc, const Number &c,
  const Number &fb, const Number &b,
  const Number &fa
) {
  Number a = c - b;

  Number gfa; ctx->penc(gfa, fa);
  Number gfb; ctx->penc(gfb, fb);
  Number gfc; ctx->penc(gfc, fc);

  SplitCommand com;
  com.adir = gfa;
  com.bdir = gfb;
  com.cdir = gfc;
  prove_positive(a, &com.avalpos);
  prove_positive(b, &com.bvalpos);

  ElGamalSecret egs;
  egs.generate(ctx->p);
  com.encrypt(egs);

  KeytieCertificate kc;
  keytie(egs, &com, &kc);

  AuthorizeCertificate acert[3];
  unsigned int n_acerts = 1;
  authorize(fa, kc, acert + 0);
  if (fa != fb)
    authorize(fb, kc, acert + n_acerts++);
  if (fa != fc && fb != fc)
    authorize(fc, kc, acert + n_acerts++);

  account->create(fa, a);
  account->create(fb, b);

  ExecuteCertificate ec;
  execute(&com, &kc, acert, n_acerts, &ec);

  account->erase(fc, c);
}

void Client::split(const Number &f, const Number &c, const Number &a) {
  Number b = c - a;

  Number gf;
  gf.powmod(ctx->g, f, ctx->p);

  SplitCommand com;
  com.adir = gf;
  com.bdir = gf;
  com.cdir = gf;
  prove_positive(a, &com.avalpos);
  prove_positive(b, &com.bvalpos);

  ElGamalSecret egs;
  egs.generate(ctx->p);
  com.encrypt(egs);

  KeytieCertificate kc;
  keytie(egs, &com, &kc);

  AuthorizeCertificate acert[1];
  authorize(f, kc, acert);
  unsigned int n_acerts = 1;

  account->create(f, a);
  account->create(f, b);

  ExecuteCertificate ec;
  execute(&com, &kc, acert, 1, &ec);

  account->erase(f, c);
}

bool Client::check(const Number &f, const Number& a) {
  Number gf;
  gf.powmod(ctx->g, f, ctx->p);

  Number ga;
  ga.powmod(ctx->g, a, ctx->p);

  CheckCommand com;
  com.adir = gf;
  com.aval = ga;

  ElGamalSecret egs;
  egs.generate(ctx->p);
  com.encrypt(egs);

  KeytieCertificate kc;
  keytie(egs, &com, &kc);

  AuthorizeCertificate acert[1];
  authorize(f, kc, acert);
  unsigned int n_acerts = 1;

  ExecuteCertificate ec;
  execute(&com, &kc, acert, 1, &ec);

  return (ec.result != 0);
}
