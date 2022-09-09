#include <stdio.h>
#include <crypt.h>

void clear(char *cs, size_t s) {
  for (size_t i = 0; i < s; i++)
    cs[i] = 0;
}

char *idris_gensalt(char *pre, unsigned long count) {
  char buf[CRYPT_GENSALT_OUTPUT_SIZE];
  return crypt_gensalt_rn(pre, count, NULL, 0, buf, CRYPT_GENSALT_OUTPUT_SIZE);
}
