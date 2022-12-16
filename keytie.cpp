#include "keytie.h"

using namespace BankOfEuler;

bool KeytieRequest::verify(CTX *ctx) {
  // must be at least p to encrypt values in this range
  // can't be more than hn because we will encrypt its exponent under sn.
  if (eg_secret.n < ctx->p || eg_secret.n >= ctx->hn)
    return false;

  if (eg_secret.g < 1 || eg_secret.g >= eg_secret.n)
    return false;
  if (eg_secret.ge < 1 || eg_secret.ge >= eg_secret.n)
    return false;
  if (eg_secret.e < 0 || eg_secret.e >= eg_secret.n - 1)
    return false;

  Number ge;
  ge.powmod(eg_secret.g, eg_secret.e, eg_secret.n);
  if (ge != eg_secret.ge)
    return false;

  return true;
}

void KeytieCertificate::generate(SCTX *sctx, const KeytieRequest &req) {
  expires = time(NULL) + sctx->expiry;
  cmd_hash = req.cmd_hash;
  eg_public = req.eg_secret;
  encrypted_e.powmod(req.eg_secret.e, sctx->se, sctx->sn);

  sctx->hash_init(h);
  sctx->hash_update(h, magic);
  sctx->hash_update(h, cmd_hash, sctx->hn);
  eg_public.hash_update(sctx, h);
  sctx->hash_update(h, encrypted_e, sctx->sn);
  sctx->hash_update(h, expires);
  sctx->hash_final(h);

  sh.powmod(h, sctx->sd, sctx->sn);
}

bool KeytieCertificate::verify(CTX *ctx) {
  if (expires < time(NULL))
    return false;

  Number h2;
  ctx->hash_init(h2);
  ctx->hash_update(h2, magic);
  ctx->hash_update(h2, cmd_hash, ctx->hn);
  eg_public.hash_update(ctx, h2);
  ctx->hash_update(h2, encrypted_e, ctx->sn);
  ctx->hash_update(h2, expires);
  ctx->hash_final(h2);

  if (h != h2)
    return false;

  return h.verify(sh, ctx->se, ctx->sn);
}

