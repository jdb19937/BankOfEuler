#include "assert.h"
#include "positive.h"
#include "authorize.h"
#include "keytie.h"
#include "bank.h"
#include "server.h"
#include "execute.h"

using namespace BankOfEuler;

Server::Server(SCTX *sctx) {
  this->sctx = sctx;

  std::string values = sctx->home + "/values";
  bank = new Bank(sctx, values.c_str());
}

Server::~Server() {
  delete bank;
}

void Server::listen(const char *sconf) {
  std::string conf = std::string(sctx->home) + std::string("/") + sconf;
  execlp("stunnel", "stunnel", conf.c_str(), NULL);
  assert(!"cannot exec stunnel, is it in your PATH?");
}

// consume http header, if available, and send http response header which
// is small enough to be buffered by stunnel in case the application insists
// on posting data before reading.  this will allow the server to be accessed
// by clients constrained to speak https.
//
// this only works because our messages never start with 'P'.
//
// returns false if the peer has disconnected since the last message.

static bool handle_http() {
  int c = getc(stdin);
  if (c == -1)
    return false;

  if (c != 'P') {
    ungetc(c, stdin);
    return true;
  }

  for (const char *p = "POST / HTTP/1."; *p; ++p)
    assert(*p == getc(stdin));

  char a1 = getc(stdin);
  while (1) {
    char a2 = getc(stdin);
    if (a1 == '\n' && a2 == '\n')
      break;
    if (a2 != '\r')
      a1 = a2;
  }

  printf(
    "HTTP/1.1 200 OK\r\n"
    "Connection: Keep-Alive\r\n"
    "Content-Type: application/x-BankOfEuler\r\n"
    "\r\n"
  );

  return true;
}

void Server::accept() {
  while (handle_http()) {
    unsigned int magic = read_int32(stdin);

    switch (magic) {
    default:
      assert(!"bad magic");

    case PositiveRequest::magic:
      {
        PositiveRequest req;
        req.read(stdin, false);
        assert(req.verify(sctx));

        PositiveChallenge chal;
        chal.generate(sctx, req);
        chal.write(stdout);
      }
      break;

    case PositiveResponse::magic:
      {
        PositiveResponse resp;
        resp.read(stdin, false);
        assert(resp.verify(sctx));

        PositiveProof proof;
        proof.generate(sctx, resp);
        proof.write(stdout);
      }
      break;

    case AuthorizeRequest::magic:
      {
        AuthorizeRequest req;
        req.read(stdin, false);
        assert(req.verify(sctx));

        AuthorizeChallenge chal;
        chal.generate(sctx, req);
        chal.write(stdout);
      }
      break;

    case AuthorizeResponse::magic:
      {
        AuthorizeResponse resp;
        resp.read(stdin, false);
        assert(resp.verify(sctx));

        AuthorizeCertificate proof;
        proof.generate(sctx, resp);
        proof.write(stdout);
      }
      break;

    case KeytieRequest::magic:
      {
        KeytieRequest req;
        req.read(stdin, false);
        assert(req.verify(sctx));

        KeytieCertificate cert;
        cert.generate(sctx, req);
        cert.write(stdout);
      }
      break;

    case ExecuteRequest::magic:
      {
        ExecuteRequest req;
        req.read(stdin, false);
        assert(req.verify(sctx));

        Number cmd_hash;
        sctx->hash_init(cmd_hash);
        req.command->hash_update(sctx, cmd_hash);
        sctx->hash_final(cmd_hash);

        Number result = bank->execute(req);

        ExecuteCertificate cert;
        cert.generate(sctx, cmd_hash, req, result);

        cert.write(stdout);
      }
      break;
    }

    fflush(stdout);
  }
}
