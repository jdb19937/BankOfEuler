#include "command.h"

using namespace BankOfEuler;

namespace BankOfEuler {

Command *read_command(FILE *fp) {
  unsigned int magic = read_int32(fp);
  Command *com = NULL;

#undef H
#define H(x) case x::magic: com = new x; break

  switch (magic) {
    H(MergeCommand);
    H(CheckCommand);
    H(SplitCommand);
  }

#undef H


  assert(com);
  com->read(fp, 0);

  return com;
}

}

bool MergeCommand::authorize(CTX *ctx, const AuthorizeCertificate *acert, unsigned int n) {
  int got_abc = 0;

//fprintf(stderr, "adir = %s\n", adir.c_str());
//fprintf(stderr, "bdir = %s\n", bdir.c_str());
//fprintf(stderr, "cdir = %s\n", cdir.c_str());
//fprintf(stderr, "acert[0].gx = %s\n", acert[0].gx.c_str());

  for (unsigned int i = 0; i < n && got_abc != 7; ++i) {
    if (acert[i].gx == adir)
      got_abc |= 1;
    if (acert[i].gx == bdir)
      got_abc |= 2;
    if (acert[i].gx == cdir)
      got_abc |= 4;
  }

  return (got_abc == 7);
}

bool SplitCommand::authorize(CTX *ctx, const AuthorizeCertificate *acert, unsigned int n) {
  int got_abc = 0;

  for (unsigned int i = 0; i < n && got_abc != 7; ++i) {
    if (acert[i].gx == adir)
      got_abc |= 1;
    if (acert[i].gx == bdir)
      got_abc |= 2;
    if (acert[i].gx == cdir)
      got_abc |= 4;
  }

  return (got_abc == 7);
}

bool CheckCommand::authorize(CTX *ctx, const AuthorizeCertificate *acert, unsigned int n) {
  int got_abc = 0;

  for (unsigned int i = 0; i < n && got_abc != 1; ++i) {
    if (acert[i].gx == adir)
      got_abc |= 1;
  }

  return (got_abc == 1);
}

