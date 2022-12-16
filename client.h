#ifndef __CLIENT_H__
#define __CLIENT_H__ 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>

#include "assert.h"
#include "positive.h"
#include "authorize.h"
#include "account.h"
#include "elgamal.h"
#include "keytie.h"
#include "ctx.h"
#include "execute.h"
#include "keytie.h"

namespace BankOfEuler {

struct ClientBase {
  CTX *ctx;
  FILE *in, *out;
  pid_t pid;

  ClientBase(CTX *ctx);
  ~ClientBase();

  void connect(const char *conf = "client.conf");
  void disconnect();
};
  
struct Client : ClientBase {
  Account *account;

  Client(CTX *ctx);
  ~Client();

  void connect(const char *conf = "bankshell.conf") {
    ClientBase::connect(conf);
  }

  void prove_positive(const Number &x, PositiveProof *proof);
  void authorize(const Number &folder, const KeytieCertificate &kcert, AuthorizeCertificate *acert);
  void keytie(const ElGamalSecret &egs, const Command *command, KeytieCertificate *cert);

  void execute(
    Command *command, KeytieCertificate *kcert,
    AuthorizeCertificate *acert, unsigned int n_acerts,
    ExecuteCertificate *ecert
  );

  void merge(const Number &f, const Number &a, const Number &b);
  void merge(
    const Number &fa, const Number &a,
    const Number &fb, const Number &b,
    const Number &fc // c = a + b
  );

  void split(
    const Number &fc, const Number &c,
    const Number &fb, const Number &b,
    const Number &fa // a = c - b
  );

  void split(const Number &f, const Number &c, const Number &a);
  bool check(const Number &f, const Number& a);
};

}
  
#endif
