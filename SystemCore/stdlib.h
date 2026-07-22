// جزء من stdlib.h (C standard - مش للتعديل)
#include <sys/types.h>

void srand(unsigned int seed);
int rand(void);
double atof(const char *nptr);
int atoi(const char *nptr);
long atol(const char *nptr);
void *malloc(size_t size);
void free(void *ptr);
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
int abs(int j);
div_t div(int numer, int denom);
//... و arc4random functions في iOS extension
u_int32_t arc4random(void);
void arc4random_buf(void *buf, size_t nbytes);
void arc4random_stir(void);
void arc4random_addrandom(u_char *dat, int datlen);