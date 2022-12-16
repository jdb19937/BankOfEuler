#include "square.h"
#include "number.h"

using namespace BankOfEuler;

const unsigned int SquareRequest::magic = 0x45;

void SquareRequest::generate(CTX *ctx, const Number &x) {
  gx.powmod(ctx->g, x, ctx->p);
  gx2.powmod(gx, x, ctx->p);
  this->n = ctx->rounds;
}

bool SquareRequest::verify(CTX *ctx) {
  if (gx < 1 || gx >= ctx->p)
    return false;
  if (gx2 < 1 || gx2 >= ctx->p)
    return false;
  if (n != ctx->rounds)
    return false;
  return true;
}

const unsigned int SquareChallenge::magic = 0x46;

void SquareChallenge::generate(SCTX *sctx, const SquareRequest &r) {
  t = time(NULL) + sctx->expiry;

  gx = r.gx;
  gx2 = r.gx2;
  unsigned int n = r.n;

  Number c;
  c.urandomb(n);

  gy.set_size(n);

  NumberVector y;
  y.set_size(n);

  for (unsigned int i = 0; i < n; ++i)
    y[i].urandomm(sctx->q);

  sctx->hash_init(h);
  sctx->hash_update(h, magic);
  sctx->hash_update(h, gx);
  sctx->hash_update(h, gx2);
  sctx->hash_update(h, t);
  sctx->hash_update(h, n);

  for (unsigned int i = 0; i < n; ++i) {
    Number hz;

    if (c.tstbit(i)) {
      gy[i].powmod(gx, y[i], sctx->p);
      hz.powmod(gx2, y[i], sctx->p);
    } else {
      gy[i].powmod(sctx->g, y[i], sctx->p);
      hz.powmod(gx, y[i], sctx->p);
    }

    sctx->hash_update(h, hz);
  }
  sctx->hash_final(h);

  sh.powmod(h, sctx->sd, sctx->sn);
}

const unsigned int SquareResponse::magic = 0x47;

void SquareResponse::generate(CTX *ctx, const SquareChallenge &c, const Number &x) {
  gx = c.gx;
  gx2 = c.gx2;
  t = c.t;
  unsigned int n = c.gy.size();
  h = c.h;
  sh = c.sh;

  gyx.set_size(n);
  for (unsigned int i = 0; i < n; ++i) {
    gyx[i].powmod(c.gy[i], x, ctx->p);
  }
}

bool SquareResponse::verify(CTX *ctx) {
  if (t < time(NULL))
    return false;

  unsigned int n = gyx.size();

  Number h2;
  ctx->hash_init(h2);
  ctx->hash_update(h2, SquareChallenge::magic);
  ctx->hash_update(h2, gx);
  ctx->hash_update(h2, gx2);
  ctx->hash_update(h2, t);
  ctx->hash_update(h2, n);
  
  for (unsigned int i = 0; i < n; ++i) {
    if (gyx[i] >= ctx->p || gyx[i] < 1) {
      return false;
    }
    ctx->hash_update(h2, gyx[i]);
  }

  ctx->hash_final(h2);
  if (h != h2)
    return false;

  return h.verify(sh, ctx->se, ctx->sn);
}

const unsigned int SquareProof::magic = 0x48;

void SquareProof::generate(SCTX *sctx, const SquareResponse &rr) {
  gx = rr.gx;
  gx2 = rr.gx2;
  n = rr.gyx.size();

  sctx->hash_init(h);
  sctx->hash_update(h, magic);
  sctx->hash_update(h, gx);
  sctx->hash_update(h, gx2);
  sctx->hash_update(h, n);
  sctx->hash_final(h);

  sh.powmod(h, sctx->sd, sctx->sn);
}

bool SquareProof::verify(CTX *ctx) {
  Number h2;
  ctx->hash_init(h2);
  ctx->hash_update(h2, magic);
  ctx->hash_update(h2, gx);
  ctx->hash_update(h2, gx2);
  ctx->hash_update(h2, n);
  ctx->hash_final(h2);

  if (h != h2)
    return false;

  return h.verify(sh, ctx->se, ctx->sn);
}
