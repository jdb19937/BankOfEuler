#ifndef __SERVER_H__
#define __SERVER_H__ 1

#include "bank.h"
#include "ctx.h"

namespace BankOfEuler {

struct Server {
  Bank *bank;
  SCTX *sctx;

  Server(SCTX *sctx);
  ~Server();

  void listen(const char *conf = "server.conf");
  void accept();
};

}

#endif
