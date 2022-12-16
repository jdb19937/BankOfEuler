#ifndef __NUMBER_H__
#define __NUMBER_H__ 1

#include <netinet/in.h>
#include <gmp.h>
#include <gmpxx.h>

#include <vector>

#include "assert.h"

namespace BankOfEuler {

// mpz_class is almost good enough, but we need custom string handling,
// file access, serialization, powermod, random values, and verification methods.

struct Number : mpz_class {
  static Number v; // multiple for '$'

  Number() : mpz_class() { }

  Number(const std::string &s) : mpz_class() {
    set_str(s);
  }

  Number(const char *p) : mpz_class() {
    set_str(p);
  }

  Number &operator = (const std::string &s) {
    set_str(s);
    return *this;
  }

  Number &operator = (const char *p) {
    set_str(p);
    return *this;
  }

#if 1
  Number(unsigned int x) : mpz_class(x) { }
  Number &operator = (unsigned int x) {
    *(mpz_class *)this = x;
    return *this;
  }

  Number(signed int x) : mpz_class(x) { }
  Number &operator = (signed int x) {
    *(mpz_class *)this = x;
    return *this;
  }

  Number(double x) : mpz_class(x) { }
  Number &operator = (double x) {
    *(mpz_class *)this = x;
    return *this;
  }

  Number(const Number &n) : mpz_class(n) { }
  Number &operator = (const Number &x) {
    *(mpz_class *)this = x;
    return *this;
  }

  Number(const mpz_class &n) : mpz_class(n) { }
  Number &operator = (const mpz_class &x) {
    *(mpz_class *)this = x;
    return *this;
  }

  template <typename A, typename B> Number(const __gmp_expr<A, B>& x) : mpz_class(x) { }
  template <typename A, typename B> Number &operator = (const __gmp_expr<A, B>& x) {
    *(mpz_class *)this = x;
    return *this;
  }
#else
  template <typename T> Number(T t) : mpz_class(t) { }

  template <typename T> Number &operator = (T t) {
    ((mpz_class &)*this) = t;
    return *this;
  }

#endif

  void _set_str_nf(const char *p);
  void set_str(const char *p);
  void set_str(const std::string &s) {
    set_str(s.c_str());
  }

  void invert(const Number &m) {
    mpz_invert(get_mpz_t(), get_mpz_t(), m.get_mpz_t());
  }

  void pow(const Number &a, unsigned int e) {
    mpz_pow_ui(get_mpz_t(), a.get_mpz_t(), e);
  }

  void powmod(const Number &x, const Number &e, const Number &m) {
    mpz_powm(get_mpz_t(), x.get_mpz_t(), e.get_mpz_t(), m.get_mpz_t());
  }

  operator std::string() const {
    return hex_string();
  }

  std::string hex_string() const {
    char buf[4096];
    assert(4096 >= mpz_sizeinbase(get_mpz_t(), 16) + 4);

    buf[0] = '0';
    buf[1] = 'x';
    mpz_get_str(buf + 2, 16, get_mpz_t());

    std::string s(buf, strlen(buf));
    return s;
  }

  const char *c_str() const {
    std::string s = hex_string();
    // fprintf(stderr, "c_str len=%d, %d\n", s.length(), strlen(s.c_str()));
    return s.c_str();
  }

  void read(FILE *fp) {
    assert(0 == fgetc(fp));
    assert(mpz_inp_raw(get_mpz_t(), fp));
    assert('\n' == fgetc(fp));
  }

  void write(FILE *fp) const {
    assert(0 == fputc(0, fp));
    assert(mpz_out_raw(fp, get_mpz_t()));
    assert('\n' == fputc('\n', fp));
  }

  unsigned int sizeinbase(unsigned int base) const {
    return mpz_sizeinbase(get_mpz_t(), base);
  }

  bool tstbit(unsigned int bit) const {
    return mpz_tstbit(get_mpz_t(), bit);
  }

  bool verify(const Number &sh, const Number &se, const Number &sn) const {
    Number v;
    v.powmod(sh, se, sn);
    return (v == *this);
  }

  void urandomb(unsigned int bits);
  void urandomm(const Number &);

  static bool randbit() {
    Number r;
    r.urandomm(2);
    return r.get_ui();
  }

  bool is_qr(const Number &p) const {
    return (mpz_legendre(get_mpz_t(), p.get_mpz_t()) == 1);
  }
};


// vector<Number> with string parsing, file access, and serialization.

struct NumberVector : std::vector<Number> {
  NumberVector() : std::vector<Number>() { }

  NumberVector(const char *p) : std::vector<Number>() {
    set_str(p);
  }

  NumberVector(std::string &s) : std::vector<Number>() {
    set_str(s);
  }

  NumberVector &operator =(const char *p) {
    set_str(p);
    return *this;
  }

  NumberVector &operator =(std::string &s) {
    set_str(s);
    return *this;
  }

  Number &get(unsigned int i) {
    return (*this)[i];
  }

  void read(FILE *fp) {
    unsigned int n;
    assert(0 == fgetc(fp));
    assert(1 == fread(&n, sizeof(n), 1, fp));
    n = ntohl(n);

    set_size(n);
    for (unsigned int i = 0; i < n; ++i)
      get(i).read(fp);
    assert('\n' == fgetc(fp));
  }

  void write(FILE *fp) const {
    unsigned int nn = htonl(size());
    assert(0 == fputc(0, fp));
    assert(1 == fwrite(&nn, sizeof(nn), 1, fp));

    for (const_iterator i = begin(); i != end(); ++i)
      i->write(fp);
    assert('\n' == fputc('\n', fp));
  }

  void set_size(unsigned int k) {
    clear();
    for (unsigned int i = 0; i < k; ++i)
      push_back(0);
  }

  void set_str(const std::string &s) {
    set_str(s.c_str());
  }
  void set_str(const char *p);
  void _set_str_nf(const char *p);

  void randomize(unsigned int k, const Number &m) {
    set_size(k);
    for (unsigned int i = 0; i < k; ++i)
      get(i).urandomm(m);
  }
};

unsigned int read_int32(FILE *);
void write_int32(unsigned int x, FILE *);

}

#endif
