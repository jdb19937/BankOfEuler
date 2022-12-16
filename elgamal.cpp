#include "elgamal.h"

using namespace BankOfEuler;

void ElGamalSecret::generate(const Number &n) {
  this->n = n;

  do {
    this->g.urandomm(n);
  } while (!g.is_qr(n));

  this->e.urandomm(n);
  this->ge.powmod(g, e, n);
}

#if ELGAMAL_TEST

main() {
  ElGamalSecret egs;
  egs.generate("111111111111111111111111111111111117");

  printf("ge = %s\n", egs.ge.c_str());

  Number x = 4;
  printf("x = %s\n", x.c_str());

  egs.encrypt(x);
  printf("ex = %s\n", x.c_str());
  egs.decrypt(x);
  printf("x = %s\n", x.c_str());
}

#endif
