#include "execute.h"

using namespace BankOfEuler;

void ExecuteRequest::generate(
  CTX *ctx,
  Command *command,
  KeytieCertificate *kcert,
  AuthorizeCertificate *acert, unsigned int n_acerts
) {
  _do_free = 0;

  this->command = command;
  this->kcert = kcert;
  this->acert = acert;
  this->n_acerts = n_acerts;
}

bool ExecuteRequest::verify(CTX *ctx) const {
  Number cmd_hash;
  ctx->hash_init(cmd_hash);
  command->hash_update(ctx, cmd_hash);
  ctx->hash_final(cmd_hash);

  if (!kcert->verify(ctx) || kcert->cmd_hash != cmd_hash)
    return false;

  for (unsigned int i = 0; i < n_acerts; ++i) {
    if (!acert[i].verify(ctx) || acert[i].ktc_hash != kcert->h)
      return false;
  }

  return true;
}

void ExecuteRequest::read(FILE *fp, bool rm) {
  _do_free = 1;

  if (rm)
    assert(magic == read_int32(fp));
  command = read_command(fp);

  kcert = new KeytieCertificate;
  kcert->read(fp);

  n_acerts = read_int32(fp);

  assert(n_acerts < max_acerts);
  if (n_acerts > 0)
    acert = new AuthorizeCertificate[n_acerts];
  for (unsigned int i = 0; i < n_acerts; ++i)
    acert[i].read(fp);
}

void ExecuteRequest::write(FILE *fp) const {
  write_int32(magic, fp);
  command->write(fp);

  kcert->write(fp);

  write_int32(n_acerts, fp);
  for (unsigned int i = 0; i < n_acerts; ++i)
    acert[i].write(fp);
}

bool ExecuteCertificate::verify(CTX *ctx) const {
  Number h2;
  ctx->hash_init(h2);
  ctx->hash_update(h2, magic);
  ctx->hash_update(h2, cmd_hash, ctx->hn);
  ctx->hash_update(h2, ktc_hash, ctx->hn);
  ctx->hash_update(h2, result, ctx->hn);
  ctx->hash_update(h2, t);
  ctx->hash_final(h2);

  if (h2 != h)
    return false;

  return h.verify(sh, ctx->se, ctx->sn);
}

void ExecuteCertificate::generate(SCTX *sctx, const Number &cmd_hash, const ExecuteRequest &req, const Number &result) {
  this->cmd_hash = cmd_hash;
  ktc_hash = req.kcert->h;
  this->result = result;

  t = time(NULL);

  sctx->hash_init(h);
  sctx->hash_update(h, magic);
  sctx->hash_update(h, cmd_hash, sctx->hn);
  sctx->hash_update(h, ktc_hash, sctx->hn);
  sctx->hash_update(h, result, sctx->hn);
  sctx->hash_update(h, t);
  sctx->hash_final(h);

  sh.powmod(h, sctx->sd, sctx->sn);
}

