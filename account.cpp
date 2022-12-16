#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "assert.h"
#include "account.h"
#include "number.h"

using namespace BankOfEuler;
using namespace std;

void Account::convert_val(const Number &f, const Number &x, string &hf, string &hx) {
  Number gx;
  gx.powmod(ctx->g, x, ctx->p);
  hx = ctx->rehash(gx);

  Number gf;
  gf.powmod(ctx->g, f, ctx->p);
  hf = ctx->rehash(gf);
}

string Account::access_val(const Number &f, const string &hf, const string &hx) {
  string dir = home + "/" + hf;
  assert(::mkdir(dir.c_str(), 0700) == 0 || errno == EEXIST);

  {
    std::string idfn = dir + "/" + ".id";
    FILE *fp = fopen(idfn.c_str(), "r");
    if (fp) {
      fclose(fp);
    } else {
      assert(fp = fopen(idfn.c_str(), "w"));
      fprintf(fp, "0x");
      mpz_out_str(fp, 16, f.get_mpz_t());
      fclose(fp);
    }
  }

  string fn = dir + "/" + hx;
  return fn;
}

void Account::create(const Number &f, const Number &x) {
  if (x == 0)
    return;
  assert(x > 0);

  string hf, hx;
  convert_val(f, x, hf, hx);
  string fn = access_val(f, hf, hx);
  string tmpfn = home + "/.tmp." + hx;

  fprintf(stderr, "writing file %s ", fn.c_str());
  fprintf(stderr, "with value %s\n", x.c_str());

  FILE *fp;
  assert(fp = fopen(tmpfn.c_str(), "w"));
  fprintf(fp, "0x");
  mpz_out_str(fp, 16, x.get_mpz_t());
  fclose(fp);

  assert(0 == rename(tmpfn.c_str(), fn.c_str()));
}

void Account::erase(const Number &f, const Number &x) {
  if (x == 0)
    return;
  string hf, hx;
  convert_val(f, x, hf, hx);
  string fn = access_val(f, hf, hx);

  fprintf(stderr, "unlinking file %s ", fn.c_str());
  fprintf(stderr, "with value %s\n", x.c_str());

  unlink(fn.c_str());
}

bool Account::exists(const Number &f, const Number &x) {
  if (x == 0)
    return true;

  string hf, hx;
  convert_val(f, x, hf, hx);
  string fn = access_val(f, hf, hx);

  FILE *fp = fopen(fn.c_str(), "r");
  if (fp)
    fclose(fp);

  return (fp != NULL);
}

unsigned int Account::list(const Number &f, NumberVector *xl) {
  Number gf;
  gf.powmod(ctx->g, f, ctx->p);
  string hf = ctx->rehash(gf);

  string dir = home + "/" + hf;

  DIR *dp;
  if (!(dp = opendir(dir.c_str())))
    return 0;

  unsigned int i = 0;
  struct dirent *de;
  while (de = readdir(dp)) {
    if (*de->d_name == '.')
      continue;

    std::string xs = string("file:") + dir + string("/") + de->d_name;
    Number x = xs;

    xl->push_back(x);
    ++i;
  }

  closedir(dp);
  return i;
}
