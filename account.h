#ifndef __ACCOUNT_H__
#define __ACCOUNT_H__ 1

#include "number.h"
#include "ctx.h"

namespace BankOfEuler {

struct Account {
  CTX *ctx;
  std::string home;

  Account(CTX *ctx, const char *home) {
    this->ctx = ctx;
    this->home = home;
  }

  bool exists(const Number &f, const Number &x);
  void create(const Number &f, const Number &x);
  void erase(const Number &f, const Number &x);
  unsigned int list(const Number &f, NumberVector *xl);

  std::string access_val(const Number &f, const std::string &hf, const std::string &hx);
  void convert_val(const Number &f, const Number &x, std::string &hf, std::string &hx);
};

}

#endif
