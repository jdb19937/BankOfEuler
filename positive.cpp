#include "positive.h"

using namespace BankOfEuler;

void PositiveRequest::generate(CTX *ctx, const Number &x, PositiveNonce *nonce) {
  Number a, b;
  mpz_sqrtrem(a.get_mpz_t(), b.get_mpz_t(), x.get_mpz_t());
  return generate(ctx, x, nonce, a, b);
}

void PositiveRequest::generate(CTX *ctx,
  const Number &x, PositiveNonce *nonce, const Number &a, const Number &b
) {
  areq.generate(ctx, a, &nonce->anonce);
  breq.generate(ctx, b, &nonce->bnonce);
  a2req.generate(ctx, a);
}

bool PositiveRequest::verify(CTX *ctx) {
  if (areq.gy.size() != breq.gy.size() || breq.gy.size() != a2req.n)
    return false;
  unsigned int n = areq.gy.size();

  if (n != ctx->rounds)
    return false;
  if (a2req.gx != areq.gx)
    return false;

  return areq.verify(ctx) && breq.verify(ctx) && a2req.verify(ctx);
}


void PositiveChallenge::generate(SCTX *sctx, const PositiveRequest &req) {
  achal.generate(sctx, req.areq);
  bchal.generate(sctx, req.breq);
  a2chal.generate(sctx, req.a2req);
}

void PositiveResponse::generate(CTX *ctx,
  const PositiveChallenge &chal,
  const Number &x, const PositiveNonce *nonce
) {
  Number a, b;
  mpz_sqrtrem(a.get_mpz_t(), b.get_mpz_t(), x.get_mpz_t());
  generate(ctx, chal, x, nonce, a, b);
}

void PositiveResponse::generate(CTX *ctx,
  const PositiveChallenge &chal,
  const Number &x, const PositiveNonce *nonce,
  const Number &a, const Number &b
) {
  aresp.generate(ctx, chal.achal, a, &nonce->anonce);
  bresp.generate(ctx, chal.bchal, b, &nonce->bnonce);
  a2resp.generate(ctx, chal.a2chal, a);
}

bool PositiveResponse::verify(CTX *ctx) {
  if (aresp.gx != a2resp.gx)
    return false;
  if (aresp.yx.size() != bresp.yx.size() || bresp.yx.size() != a2resp.gyx.size())
    return false;
  return aresp.verify(ctx) && bresp.verify(ctx) && a2resp.verify(ctx);
}

void PositiveProof::generate(SCTX *sctx, const PositiveResponse &resp) {
  gx = (resp.a2resp.gx2 * resp.bresp.gx) % sctx->p;
  n = resp.aresp.yx.size();
  t = time(NULL) + sctx->expiry;

  sctx->hash_init(h);
  sctx->hash_update(h, magic);
  sctx->hash_update(h, gx);
  sctx->hash_update(h, t);
  sctx->hash_update(h, n);
  sctx->hash_final(h);

  sh.powmod(h, sctx->sd, sctx->sn);
}

bool PositiveProof::verify(CTX *ctx) const {
  if (t < time(NULL))
    return false;

  Number h2;
  ctx->hash_init(h2);
  ctx->hash_update(h2, magic);
  ctx->hash_update(h2, gx);
  ctx->hash_update(h2, t);
  ctx->hash_update(h2, n);
  ctx->hash_final(h2);

  if (h != h2)
    return false;

  return h.verify(sh, ctx->se, ctx->sn);
}

