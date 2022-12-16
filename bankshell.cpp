#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#include "number.h"
#include "bank.h"
#include "server.h"
#include "client.h"
#include "ctx.h"

using namespace BankOfEuler;

void usage() {
  fprintf(stderr,
    "Usage: bankshell [options] command [args ...]\n"
    "Options:\n"
    "  -h               this help\n"
    "  -d directory     use client configuration in this directory\n"
    "                   default is $BANKOFEULER_HOME, or else /usr/local/BankOfEuler\n"
    "Commands:\n"
    "  list             show all values in account\n"
    "  merge            \n"
    "  split            \n"
    "  check            \n"
    "  sync             \n"
    "  randomize        \n"
  );
}

static Number get_aopt(int &argc, char **&argv, const Number &df) {
  if (argc <= 0)
    return df;

  if (!strcmp(*argv, "-a")) {
    Number ret;
    ++argv; --argc;

    assert(argc > 0);
    ret = *argv;
    ++argv; --argc;
    
    return ret;
  }

  return df;
}


int _main(int argc, char **argv) {
  --argc;
  ++argv;

  if (argc < 1) {
    usage();
    return 1;
  }

  while (argc > 0 && **argv == '-') {
    if (!strcmp(*argv, "--")) {
      --argc;
      ++argv;
      break;
    }

    if (!strcmp(*argv, "-d")) {
      --argc;
      ++argv;

      assert(argc);
      const char *home = *argv;

      --argc;
      ++argv;

      static char putenvstr[4096];
      snprintf(putenvstr, sizeof(putenvstr), "BANKOFEULER_HOME=%s", home);
      assert(0 == putenv(putenvstr));

      continue;
    }

    if (!strcmp(*argv, "-h")) {
      usage();
      return 0;
    }

    usage();
    return 1;
  }

  if (!argc)
    usage();
  std::string cmd = *argv;
  --argc;
  ++argv;

  CTX ctx;
  Client client(&ctx);

  Account *account = client.account;
  assert(account);

  if (cmd == "merge") {
    client.connect();
    assert(argc > 0);
    Number fa = get_aopt(argc, argv, -1);
    assert(fa != -1);

    assert(argc > 0);
    Number a = *argv;
    ++argv; --argc;

    assert(argc > 0);
    Number fb = get_aopt(argc, argv, fa);
    assert(argc > 0);

    do {
      Number b = *argv;
      ++argv; --argc;

      Number fc = get_aopt(argc, argv, fb);
      client.merge(fa, a, fb, b, fc);

      a += b;
      fa = fc;
      fb = fc;
    } while (argc > 0);

    return 0;
  }

  if (cmd == "split") {
    client.connect();
    assert(argc > 0);
    Number fc = get_aopt(argc, argv, -1);
    assert(fc != -1);

    assert(argc > 0);
    Number c = *argv;
    ++argv; --argc;

    assert(argc > 0);
    Number fb = get_aopt(argc, argv, fc);
    assert(argc > 0);

    do {
      Number b = *argv;
      ++argv; --argc;

      Number fa = get_aopt(argc, argv, fb);
      client.split(fc, c, fb, b, fa);

      c -= b;
      fc = fa;
      fb = fa;
    } while (argc > 0);

    return 0;
  }

  if (cmd == "check") {
    client.connect();
    Number f = -1;
    assert(argc > 0);

    while (argc > 0) {
      assert(-1 != (f = get_aopt(argc, argv, f)));
      assert(argc > 0);

      Number a = *argv;
      ++argv; --argc;

      fprintf(stderr, "%s has %svalue\n", a.c_str(),
        client.check(f, a) ? "" : "no ");
    }

    return 0;
  }

  if (cmd == "randomize") {
    client.connect();
    Number f = -1;
    Number rm = "$1";
    rm >>= 64;

    assert(argc > 0);
    while (argc > 0) {
      assert(-1 != (f = get_aopt(argc, argv, f)));
      assert(argc > 0);

      Number x = *argv;
      ++argv; --argc;

      Number r;
      r.urandomm(rm);

      Number b;
      b.urandomm(2);

      if (b == 0) {
        client.split(f, x, x - r);
      } else {
        client.split(f, x, r);
      }
    }

    return 0;
  }

  if (cmd == "sync") {
    client.connect();
    Number f = -1;
    assert(argc > 0);

    while (argc > 0) {
      assert(-1 != (f = get_aopt(argc, argv, f)));
      assert(argc > 0);

      Number x = *argv;
      ++argv; --argc;

      if (client.check(f, x))
        account->create(f, x);
      else
        account->erase(f, x);
    }

    return 0;
  }

  if (cmd == "list") {
    Number f = -1;
    assert(-1 != (f = get_aopt(argc, argv, f)));

    NumberVector xl;
    account->list(f, &xl);
    unsigned int xln = xl.size();
    for (unsigned int i = 0; i < xln; ++i) {
      std::string xs = xl[i];
      printf("%s\n", xs.c_str());
    }
    return 0;
  }

  usage();
  return 1;
}

int main(int argc, char **argv) {
  try {
    return _main(argc, argv);
  } catch (const FailedAssertion &e) {
    fprintf(stderr, "%s\n", e.c_str());
  }
  fprintf(stderr, "bankshell: caught exception, aborting\n");
  return 1;
}
