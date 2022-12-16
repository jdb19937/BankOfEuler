// just for fun

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netinet/in.h>

#include <gmpxx.h>

void usage() {
  fprintf(stderr, "Usage: qrspiral modulus [scale [image_width [count]]]\n");
  fprintf(stderr, "\tProduce a pgm file representing the quadratic residuosity of a number.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "\tmodulus      The modulus under which to compute the Jacobi symbol\n");
  fprintf(stderr, "\tscale        How many powers of 2 to scale the image? (default 0)\n");
  fprintf(stderr, "\timage_width  Width and height of output pgm file (default 512)\n");
  fprintf(stderr, "\tcount        Output count pgm files, concatenated, starting with modulus (default 1)\n");
}

int main(int argc, char **argv) {
  mpz_class np, nq;
  mpz_class nitop;
  mpz_class ni;

  if (argc < 2) {
    usage();
    return 1;
  }
  np = argv[1];
  if (0 == np % 2)
    ++np;

  int scale = argc > 2 ? atoi(argv[2]) : 0;
  int j = argc > 3 ? atoi(argv[3]) : 512;
  int count = argc > 4 ? atoi(argv[4]) : 1;

  int jb = (j << scale);
  int jj = j * j;

  unsigned short *data = new unsigned short[jj];

  nq = np;
  nq += 2 * count;

  for (; np < nq; np += 2) {
    for (int i = 0; i < jj; ++i)
      data[i] = 0x7FFF;

    nitop = jb * jb;
    ni = 0;
  
    int x = jb/2-1;
    int y = jb/2-1;
    int amt = (0xFFFF >> (scale * 2 + 1));
  
    for (int k = 0; k < jb; k += 2) {
      for (int l = -1; l < k && ni < nitop; ++l) {
        assert(x >= 0 && x < jb && y >= 0 && y < jb);
        int l = mpz_jacobi(ni.get_mpz_t(), np.get_mpz_t());
        data[(y>>scale) * j + (x>>scale)] += amt * l;
        ++ni;
        ++x;
      }
  
      for (int l = -1; l < k && ni < nitop; ++l) {
        assert(x >= 0 && x < jb && y >= 0 && y < jb);
        int l = mpz_jacobi(ni.get_mpz_t(), np.get_mpz_t());
        data[(y>>scale) * j + (x>>scale)] += amt * l;
        ++ni;
        ++y;
      }
  
      for (int l = -2; l < k && ni < nitop; ++l) {
        assert(x >= 0 && x < jb && y >= 0 && y < jb);
        int l = mpz_jacobi(ni.get_mpz_t(), np.get_mpz_t());
        data[(y>>scale) * j + (x>>scale)] += amt * l;
        ++ni;
        --x;
      }
  
      for (int l = -2; l < k && ni < nitop; ++l) {
        assert(x >= 0 && x < jb && y >= 0 && y < jb);
        int l = mpz_jacobi(ni.get_mpz_t(), np.get_mpz_t());
        data[(y>>scale) * j + (x>>scale)] += amt * l;
        ++ni;
        --y;
      }
    }

    assert(ni == nitop);

    printf("P5\n%d %d\n65535\n", j, j);

    for (int i = 0; i < jj; ++i)
      data[i] = htons(data[i]);
  
    assert(jj == fwrite(data, sizeof(*data), jj, stdout));
  }
  
  delete[] data;
  return 0;
}
