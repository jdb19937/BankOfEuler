#include "small.h"
#include "number.h"

using namespace BankOfEuler;

const unsigned int SmallRequest::magic = 0x56;

bool SmallRequest::verify(CTX *ctx) {
  if (gx < 1 || gx >= ctx->p)
    return false;

  unsigned int n = gy.size();
  if (n != ctx->rounds)
    return false;

  for (unsigned int i = 0; i < n; ++i)
    if (gy[i] < 1 || gy[i] >= ctx->p)
       return false;

  return true;
}

void SmallRequest::generate(CTX *ctx, const Number &x, SmallNonce *nonce) {
  unsigned int n = ctx->rounds;
  nonce->y.set_size(n);
  assert(x < ctx->k);
  nonce->y.randomize(n, ctx->k - x); // x << k, so k - x is almost k

  gx.powmod(ctx->g, x, ctx->p);
  gy.set_size(n);

  for (unsigned int i = 0; i < n; ++i) {
    gy[i].powmod(ctx->g, nonce->y[i], ctx->p);
  }
}

const unsigned int SmallChallenge::magic = 0x57;

void SmallChallenge::generate(SCTX *sctx, const SmallRequest &r) {
  t = time(NULL) + sctx->expiry;

  gx = r.gx;
  unsigned int n = r.gy.size();
  c.urandomb(n);

  sctx->hash_init(h);
  sctx->hash_update(h, magic);
  sctx->hash_update(h, gx);
  sctx->hash_update(h, t);
  sctx->hash_update(h, n);

  Number t;
  for (unsigned int i = 0; i < n; ++i) {
    if (c.tstbit(i)) {
      t = r.gy[i] * gx;
      t %= sctx->p;
    } else {
      t = r.gy[i];
    }

    sctx->hash_update(h, t);
  }

  sctx->hash_final(h);
  
  sh.powmod(h, sctx->sd, sctx->sn);
}

const unsigned int SmallResponse::magic = 0x58;

bool SmallResponse::verify(CTX *ctx) {
  if (t < time(NULL))
    return false;

  unsigned int n = yx.size();

  Number h2;
  ctx->hash_init(h2);
  ctx->hash_update(h2, SmallChallenge::magic);
  ctx->hash_update(h2, gx);
  ctx->hash_update(h2, t);
  ctx->hash_update(h2, n);

  for (unsigned int i = 0; i < n; ++i) {
    if (yx[i] < 0 || yx[i] >= ctx->k)
      return false;

    Number gy;
    gy.powmod(ctx->g, yx[i], ctx->p);
    ctx->hash_update(h2, gy);
  }

  ctx->hash_final(h2);
  if (h != h2)
    return false;

  return h.verify(sh, ctx->se, ctx->sn);
}


void SmallResponse::generate(CTX *ctx, const SmallChallenge &c, const Number &x, const SmallNonce *nonce) {
  gx = c.gx;
  h = c.h;
  sh = c.sh;
  t = c.t;

  unsigned int n = nonce->y.size();
  yx.set_size(n);

  for (unsigned int i = 0; i < n; ++i) {
    yx[i] = nonce->y[i];
    if (c.c.tstbit(i))
      yx[i] += x;
  }
}

const unsigned int SmallProof::magic = 0x59;

void SmallProof::generate(SCTX *sctx, const SmallResponse &r) {
  gx = r.gx;
  n = r.yx.size();
  t = time(NULL);

  sctx->hash_init(h);
  sctx->hash_update(h, magic);
  sctx->hash_update(h, gx);
  sctx->hash_update(h, t);
  sctx->hash_update(h, n);
  sctx->hash_final(h);

  sh.powmod(h, sctx->sd, sctx->sn);
}

bool SmallProof::verify(CTX *ctx) {
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
