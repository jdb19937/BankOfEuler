#include "number.h"
#include "authorize.h"

using namespace BankOfEuler;

bool AuthorizeRequest::verify(CTX *ctx) {
  if (gx < 1 || gx >= ctx->p)
    return false;
  if (gr < 1 || gr >= ctx->p)
    return false;
  if (ktc_hash < 0 || ktc_hash >= ctx->hn)
    return false;

  return true;
}

void AuthorizeRequest::generate(
  CTX *ctx, const Number &x,
  const Number &ktc_hash,
  AuthorizeNonce *nonce
) {
  nonce->r.urandomm(ctx->q);

  this->ktc_hash = ktc_hash;
  gx.powmod(ctx->g, x, ctx->p);
  gr.powmod(ctx->g, nonce->r, ctx->p);
}

void AuthorizeChallenge::generate(SCTX *sctx, const AuthorizeRequest &req) {
  t = time(NULL) + sctx->expiry;

  c.urandomm(sctx->q);

  sctx->hash_init(h);
  sctx->hash_update(h, magic);
  sctx->hash_update(h, req.gx);
  sctx->hash_update(h, req.gr);
  sctx->hash_update(h, c);
  sctx->hash_update(h, t);
  sctx->hash_update(h, req.ktc_hash, sctx->hn);
  sctx->hash_final(h);

  sh.powmod(h, sctx->sd, sctx->sn);
}

bool AuthorizeResponse::verify(CTX *ctx) {
  if (t < time(NULL))
    return false;

  Number gcxr;
  gcxr.powmod(ctx->g, cxr, ctx->p);

  Number gcxr2;
  gcxr2.powmod(gx, c, ctx->p);
  gcxr2 *= gr;
  gcxr2 %= ctx->p;

  if (gcxr != gcxr2)
    return false;

  Number h2;
  ctx->hash_init(h2);
  ctx->hash_update(h2, AuthorizeChallenge::magic);
  ctx->hash_update(h2, gx);
  ctx->hash_update(h2, gr);
  ctx->hash_update(h2, c);
  ctx->hash_update(h2, t);
  ctx->hash_update(h2, ktc_hash, ctx->hn);
  ctx->hash_final(h2);

  if (h != h2)
    return false;

  return h.verify(sh, ctx->se, ctx->sn);
}


void AuthorizeResponse::generate(CTX *ctx,
  const AuthorizeChallenge &chal, const Number &x,
  const Number &ktc_hash,
  const AuthorizeNonce *nonce
) {
  gx.powmod(ctx->g, x, ctx->p);
  gr.powmod(ctx->g, nonce->r, ctx->p);
  this->ktc_hash = ktc_hash;

  c = chal.c;
  t = chal.t;
  h = chal.h;
  sh = chal.sh;

  cxr = c * x + nonce->r;
}

void AuthorizeCertificate::generate(SCTX *sctx, const AuthorizeResponse &resp) {
  gx = resp.gx;
  ktc_hash = resp.ktc_hash;
  t = time(NULL) + sctx->expiry;

  sctx->hash_init(h);
  sctx->hash_update(h, magic);
  sctx->hash_update(h, gx);
  sctx->hash_update(h, t);
  sctx->hash_update(h, ktc_hash, sctx->hn);
  sctx->hash_final(h);

  sh.powmod(h, sctx->sd, sctx->sn);
}

bool AuthorizeCertificate::verify(CTX *ctx) {
  if (t < time(NULL))
    return false;
  if (gx < 1 || ctx->p <= gx)
    return false;

  Number h2;
  ctx->hash_init(h2);
  ctx->hash_update(h2, magic);
  ctx->hash_update(h2, gx);
  ctx->hash_update(h2, t);
  ctx->hash_update(h2, ktc_hash, ctx->hn);
  ctx->hash_final(h2);

  if (h != h2)
    return false;

  return h.verify(sh, ctx->se, ctx->sn);
}
