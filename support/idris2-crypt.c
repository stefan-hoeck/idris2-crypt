#include <stdio.h>
#include <crypt.h>

void clear(char *cs, size_t s) {
  for (size_t i = 0; i < s; i++)
    cs[i] = 0;
}

char *idris_gensalt(const char *prefix, unsigned long count) {
  return crypt_gensalt_ra(prefix, count, NULL, 0);
}
