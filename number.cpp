#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "number.h"

using namespace BankOfEuler;

static FILE *urfp = NULL;
Number Number::v = 0;

void Number::urandomb(unsigned int bits) {
  if (!urfp)
    assert(urfp = fopen("/dev/urandom", "r"));

  unsigned int bytes = (bits + 7) >> 3;
  assert(bytes);

  unsigned char buf[bytes];
  size_t bytes2 = fread(buf, 1, bytes, urfp);
  assert(bytes == bytes2);

  mpz_import(get_mpz_t(), bytes, 1, 1, 0, 0, buf);

  if (unsigned int trim = bytes * 8 - bits) {
    *this >>= trim;
  }
}

void Number::urandomm(const Number &m) {
  // 128 extra bits to hide bias
  unsigned int bits = 128 + m.sizeinbase(2);
  urandomb(bits);
  *this %= m;
}

void Number::set_str(const char *p) {
  bool is_file = false;
  FILE *fp;

  if (!strncmp(p, "file:", 5)) {
    p += 5;
    assert(fp = fopen(p, "r"));
    is_file = true;
  } else if (!isdigit(*p) && *p != '$' && *p != '-') {
    fp = fopen(p, "r");
    if (fp)
      is_file = true;
  }

  if (is_file) {
    if (getc(fp) == 0) {
      fseek(fp, 0, 0);
      read(fp);
      fclose(fp);
      return;
    }

    assert(0 == fseek(fp, 0, 2));
    unsigned int bufn = ftell(fp);
    assert(0 == fseek(fp, 0, 0));
    char buf[bufn + 1];

    assert(bufn == fread(buf, 1, bufn, fp) || !"can't read file");
    buf[bufn] = 0;

    if (char *p = strchr(buf, '\n'))
      *p = 0;

    fclose(fp);

    _set_str_nf(buf);

    return;
  }

  _set_str_nf(p);
}

void Number::_set_str_nf(const char *p) {
  if (p[0] == '$') {
    mpf_class f(p + 1, 1024);
    Number big;
    big.pow(10, 128);
    f *= big;

    Number z = f;
    z *= Number::v;
    z /= big;

    *this = z;

#if 0
    double f = exp2(64);
    double d = f * strtod(p + 1, NULL);
    *this = (d * v) / f;
#endif

    return;
  }

  if (p[0] == '-' || p[0] >= '0' && p[0] <= '9') { // dec, hex, oct
    assert(0 == mpz_set_str(get_mpz_t(), p, 0));
    // *(mpz_class *)this = p;
    return;
  }

  assert(!"can't understand number");
}

void NumberVector::set_str(const char *p) {
  clear();

  if (!strncmp(p, "file:", 5)) {
    FILE *fp;
    assert(fp = fopen(p + 5, "r"));

    if (getc(fp) == 0) {
      fseek(fp, 0, 0);
      read(fp);
      fclose(fp);
      return;
    }

    assert(0 == fseek(fp, 0, 2));
    unsigned int bufn = ftell(fp);
    assert(0 == fseek(fp, 0, 0));
    char buf[bufn + 1];

    assert(bufn == fread(buf, 1, sizeof(buf), fp) || !"can't read file");
    buf[bufn] = 0;
    fclose(fp);

    _set_str_nf(buf);
    return;
  }

  if (*p == '(')
    ++p;

  _set_str_nf(p);
}

void NumberVector::_set_str_nf(const char *p) {
  const char *q;

  do {
    while (*p && isspace(*p))
      ++p;
    if (!*p)
      break;
    q = p;
    while (*q && !isspace(*q) && *q != ')')
      ++q;

    char buf[1 + q - p];
    memcpy(buf, p, q - p);
    buf[q - p] = 0;

    push_back(0);
    back().set_str(buf);

    p = q + 1;
  } while (*q);
}

namespace BankOfEuler {

void write_int32(unsigned int x, FILE *fp) {
  unsigned int nx = htonl(x);
  assert('\1' == fputc('\1', fp));
  assert(1 == fwrite(&nx, sizeof(nx), 1, fp));
  assert('\n' == fputc('\n', fp));
}

unsigned int read_int32(FILE *fp) {
  unsigned int nx;
  assert('\1' == fgetc(fp));
  assert(1 == fread(&nx, sizeof(nx), 1, fp));
  assert('\n' == fgetc(fp));
  return ntohl(nx);
}

}
