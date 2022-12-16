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
    "Usage: bankadmin [options] command [args ...]\n"
    "Options:\n"
    "  -h               this help\n"
    "  -d directory     use client configuration in this directory\n"
    "                   default is $BANKOFEULER_HOME, or else /usr/local/BankOfEuler\n"
    "Commands:\n"
    "  create -a account value\n"         
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

  SCTX sctx;
  std::string values = sctx.home + "/values";
  Bank bank(&sctx, values.c_str());
  Number fa = -1;
  Number gfa;

  if (cmd == "create") {
    assert(argc > 0);

    while (argc > 0) {
      fa = get_aopt(argc, argv, fa);
      assert(fa != -1);
      assert(argc > 0);

      Number a = *argv;
      ++argv; --argc;

      Number gfa;
      sctx.penc(gfa, fa);
      std::string hfa = sctx.rehash(gfa);

      Number ga;
      sctx.penc(ga, a);
      std::string ha = sctx.rehash(ga);

      fprintf(stderr, "creating %s/%s\n", hfa.c_str(), ha.c_str());
      bank.create(hfa, ha);
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

  fprintf(stderr, "bankadmin: caught exception, aborting\n");
  return 1;
}

