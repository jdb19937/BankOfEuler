#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>

#include "number.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

#include "assert.h"
#include "ctx.h"
#include "client.h"

namespace BankOfEuler {

struct CoinClient : ClientBase {
  CoinClient(CTX *ctx) : ClientBase(ctx), be_client(ctx) { }
  ~CoinClient() { }

  Client be_client;

  void connect(const char *conf = "coinflip.conf") {
    ClientBase::connect(conf);
  }

  Number decide_bet();
  Number prepare_bet(const Number &f, const Number &bet);
  int main(const Number &ac1);
};

}

using namespace BankOfEuler;

Number CoinClient::decide_bet() {
  Number bet0 = "$1";
  Number small = bet0;
  small >>= 64;

  Number rsmall;
  rsmall.urandomm(small * 2);
  rsmall -= small;
  rsmall >>= 1;

  Number bet1 = bet0 + rsmall;

  Number gbet1;
  ctx->penc(gbet1, bet1);
  gbet1.write(out);

  Number gbet2;
  gbet2.read(in);

  bet1.write(out);

  Number bet2;
  bet2.read(in);

  Number gbet2b;
  ctx->penc(gbet2b, bet2);
  assert(gbet2b == gbet2);

  Number bet = (bet1 + bet2) >> 1;
  assert(bet >= bet - small && bet < bet + small);

  return bet;
}

Number CoinClient::prepare_bet(const Number &f, const Number &bet) {
  Account *a = be_client.account;

  Number wad;
  NumberVector val;
  a->list(f, &val);
  for (unsigned int i = 0; i < val.size(); ++i) {
    if (val[i] > bet) {
      wad = val[i];
      break;
    }
  }
  assert(wad != 0 && "can't find wad greater than bet");
  be_client.split(f, wad, f, bet, f);
  return wad - bet;
}
  

int CoinClient::main(const Number &ac1) {
  connect();
  be_client.connect("bankshell.conf");

  int which = read_int32(in);
  fprintf(stderr, "i am %d\n", which);

  Number bet = decide_bet();
  fprintf(stderr, "bet is %s\n", bet.c_str());

  Number gac1;
  ctx->penc(gac1, ac1);
  gac1.write(out);

  Number gac2;
  gac2.read(in);

  Number wad = prepare_bet(ac1, bet);
fprintf(stderr, "prepared bet %s\n", bet.c_str());

  Number betwin = bet * 2;
  Number gbet, gbetwin;
  ctx->penc(gbet, bet);
  gbetwin = (gbet * gbet) % ctx->p;

  if (which) {
    ElGamalSecret egs;
    egs.generate(ctx->p);

    Number enc1 = gac1, enc2 = gac2, r1, r2;
    r1 = egs.encrypt(enc1);
    r2 = egs.encrypt(enc2);

    MergeCommand com1;
    KeytieCertificate kt1;
    AuthorizeCertificate auth1;
    com1.adir = gac1; com1.bdir = gac2; com1.cdir = enc1;
    com1.aval = gbet; com1.bval = gbet;
    be_client.keytie(egs, &com1, &kt1);
    be_client.authorize(ac1, kt1, &auth1);

    MergeCommand com2;
    KeytieCertificate kt2;
    AuthorizeCertificate auth2;
    com2.adir = gac1; com2.bdir = gac2; com2.cdir = enc2;
    com2.aval = gbet; com2.bval = gbet;
    be_client.keytie(egs, &com2, &kt2);
    be_client.authorize(ac1, kt2, &auth2);

    Number swap;
    swap.urandomb(1);
    if (swap == 1) {
      com2.write(out); kt2.write(out); auth2.write(out);
      com1.write(out); kt1.write(out); auth1.write(out);
    } else {
      com1.write(out); kt1.write(out); auth1.write(out);
      com2.write(out); kt2.write(out); auth2.write(out);
    }

    unsigned int n = 128;
    write_int32(n, out);

    Number *enc3l = new Number[n];
    Number *enc4l = new Number[n];
    Number *r3l = new Number[n];
    Number *r4l = new Number[n];

    Number swapped;
    swapped.urandomb(n);

    for (unsigned int i = 0; i < n; ++i) {
      if (swapped.tstbit(i) == 0) {
        enc3l[i] = gac1;
        enc4l[i] = gac2;
      } else {
        enc3l[i] = gac2;
        enc4l[i] = gac1;
      }
      r3l[i] = egs.encrypt(enc3l[i]);
      r4l[i] = egs.encrypt(enc4l[i]);
      enc3l[i].write(out);
      enc4l[i].write(out);
    }

    Number chal;
    chal.read(in);

    for (unsigned int i = 0; i < n; ++i) {
      if (chal.tstbit(i)) {
        r3l[i].write(out);
        r4l[i].write(out);
      } else {
        if (swapped.tstbit(i) == 0) {
          Number r3 = r3l[i] - r1;
          Number r4 = r4l[i] - r2;
          r3.write(out);
          r4.write(out);
        } else {
          Number r3 = r3l[i] - r2;
          Number r4 = r4l[i] - r1;
          r3.write(out);
          r4.write(out);
        }
      }
    }

    Number choice;
    choice.read(in);
    fprintf(stderr, "opponent choice %s\n", choice.c_str());
  } else {
    alarm(1000);

    MergeCommand coma;
    KeytieCertificate kta;
    AuthorizeCertificate autha;
    coma.read(in); kta.read(in); autha.read(in);
    Number comah;
    ctx->hash_init(comah);
    coma.hash_update(ctx, comah);
    ctx->hash_final(comah);
    assert(coma.adir == gac2 && coma.bdir == gac1);
    assert(coma.aval == gbet && coma.bval == gbet);
    assert(kta.verify(ctx));
    assert(kta.expires > time(NULL) + 1800);
    assert(autha.verify(ctx));
    assert(autha.t > time(NULL) + 1800);
    assert(kta.cmd_hash == comah);
    assert(autha.ktc_hash == kta.h);
    Number enca = coma.cdir;

    MergeCommand comb;
    KeytieCertificate ktb;
    AuthorizeCertificate authb;
    comb.read(in); ktb.read(in); authb.read(in);
    Number combh;
    ctx->hash_init(combh);
    comb.hash_update(ctx, combh);
    ctx->hash_final(combh);
    assert(comb.adir == gac2 && comb.bdir == gac1);
    assert(comb.aval == gbet && comb.bval == gbet);
    assert(ktb.verify(ctx));
    assert(ktb.expires > time(NULL) + 1800);
    assert(authb.verify(ctx));
    assert(authb.t > time(NULL) + 1800);
    assert(ktb.cmd_hash == combh);
    assert(authb.ktc_hash == ktb.h);
    Number encb = comb.cdir;

    assert(ktb.eg_public == kta.eg_public);
    ElGamalPublic egp = ktb.eg_public;
    assert(egp.n == ctx->p);
    assert(egp.g.is_qr(egp.n));

    unsigned int n = read_int32(in);
    assert(n >= 128 && n <= 256);

    Number *enc3l = new Number[n];
    Number *enc4l = new Number[n];
    for (unsigned int i = 0; i < n; ++i) {
      enc3l[i].read(in);
      enc4l[i].read(in);
    }

    Number chal;
    chal.urandomb(n);
    chal.write(out);

    for (unsigned int i = 0; i < n; ++i) {
      Number r3, r4;
      r3.read(in);
      r4.read(in);
      egp.decrypt(enc3l[i], r3);
      egp.decrypt(enc4l[i], r4);

      if (chal.tstbit(i)) {
        assert(enc3l[i] == gac1 && enc4l[i] == gac2 || enc3l[i] == gac2 && enc4l[i] == gac1);
      } else {
        assert(enc3l[i] == enca && enc4l[i] == encb || enc3l[i] == encb && enc4l[i] == enca);
      }
    }

    ExecuteCertificate ecert;
    AuthorizeCertificate acert[2];
    Number choice;
    choice.urandomb(1);

fprintf(stderr, "made choice %d\n", choice.get_si());

    if (choice == 0) {
      acert[0] = autha;
      be_client.authorize(ac1, kta, acert + 1);
      be_client.execute(&coma, &kta, acert, 2, &ecert);
    } else {
      acert[0] = authb;
      be_client.authorize(ac1, ktb, acert + 1);
      be_client.execute(&comb, &ktb, acert, 2, &ecert);
    }

    choice.write(out);
  }

  if (be_client.check(ac1, betwin)) {
    fprintf(stderr, "YOU WIN!\n");
    be_client.account->create(ac1, betwin);
    be_client.merge(ac1, wad, ac1, betwin, ac1);
    be_client.account->erase(ac1, bet);
  } else if (be_client.check(ac1, bet)) {
    fprintf(stderr, "(YOU DID NOT LOSE, RECOVERING BET!)\n");
    be_client.merge(ac1, wad, ac1, bet, ac1);
  } else {
    fprintf(stderr, "YOU LOSE!\n");
    be_client.account->erase(ac1, bet);
  }
  
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr,
      "Usage: coinflip folder\n"
      "\n"
      "Connect to flipserve to find a peer, and bet ~$1 on a fair coin.\n"
      "The ~$1 will be split from the first larger value found in the\n"
      "specified specified.\n"
    );
    return 1;
  }

  Number f = argv[1];

  try {
    CTX ctx;
    CoinClient cc(&ctx);
    return cc.main(f);
  } catch (FailedAssertion &fas) {
    fprintf(stderr, "%s: %s\n", argv[0], fas.c_str());
    return 1;
  }
}
