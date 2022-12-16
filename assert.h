#ifndef __ASSERT_H__
#define __ASSERT_H__ 1

#include "assert.h"

#include <string>

namespace BankOfEuler {

struct FailedAssertion {
  std::string file;
  unsigned int line;
  std::string cond;

  FailedAssertion(const char *file, unsigned int line, const char *cond) {
    this->file = file;
    this->line = line;
    this->cond = cond;
  }

  std::string message() const {
    char buf[4096];
    snprintf(buf, sizeof(buf), "%s:%d: assertion failed: %s", file.c_str(), line, cond.c_str());
    return std::string(buf);
  }

  operator std::string() const {
    return message();
  }

  const char *c_str() const {
    return message().c_str();
  }
};

}

#undef assert
#define assert(x) do { \
  if (!(x)) throw BankOfEuler::FailedAssertion(__FILE__, __LINE__, #x); \
} while (0)

#endif
