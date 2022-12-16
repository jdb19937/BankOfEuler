#ifndef __BANK_H__
#define __BANK_H__ 1

#include <string>

#include "number.h"
#include "command.h"
#include "execute.h"
#include "ctx.h"

namespace BankOfEuler {

struct Bank {
  SCTX *sctx;
  std::string home;

  Bank(SCTX *sctx, const char *home) {
    this->sctx = sctx;
    this->home = home;
  }

  bool exists(const std::string &, const std::string &);
  bool create(const std::string &, const std::string &);
  bool erase(const std::string &, const std::string &);
  bool touch(const std::string &, const std::string &);

  Number execute(const Command *command);
  Number execute(const MergeCommand *command);
  Number execute(const CheckCommand *command);
  Number execute(const SplitCommand *command);

  Number execute(const ExecuteRequest &req);
};

}

#endif
