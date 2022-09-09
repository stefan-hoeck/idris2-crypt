#include <stdio.h>
#include <crypt.h>
#include <string.h>

// Set all characters in a char array to 0
void clear(char *cs, size_t s) {
  for (size_t i = 0; i < s; i++)
    cs[i] = 0;
}

// Generate a random salt for a hashing function
// `pre` and `count` can only take specific values,
// so Idris API must make sure that only valid values
// are passed to the FFI
char *idris_gensalt(const char *pre, unsigned long count) {
  char buf[CRYPT_GENSALT_OUTPUT_SIZE];
  return crypt_gensalt_rn(pre, count, NULL, 0, buf, CRYPT_GENSALT_OUTPUT_SIZE);
}

// Encrypt a passphrase with the given salt
// This will fail if the salt is not valid, so on the Idris
// side we want to make sure to validate the salt before calling this
char *idris_crypt(const char *salt, const char *phrase) {
  struct crypt_data cd;
  clear(cd.output, CRYPT_OUTPUT_SIZE);
  clear(cd.setting, CRYPT_OUTPUT_SIZE);
  clear(cd.input, CRYPT_MAX_PASSPHRASE_SIZE);
  cd.initialized = 0;

  stpncpy(cd.setting, salt, CRYPT_OUTPUT_SIZE);
  stpncpy(cd.input, phrase, CRYPT_MAX_PASSPHRASE_SIZE);

  return crypt_r(phrase, salt, &cd);
}

// Check a cleartext passphrase (`phrase`) against an encrypted
// passphrase (`key`). `key` must be usable as a valid salt
// so this should be verified on the Idris side before invoking this
int idris_crypt_check(const char *key, const char *phrase) {
  return strcmp(key, idris_crypt(key, phrase));
}

// Check if the given string can be used as a valid salt
// for encrypting a passphrase.
int idris_checksalt(const char *salt) {
  return crypt_checksalt(salt);
}

// Check if the given passphrase is not too long for encryption.
int idris_checkphrase(const char *phrase) {
  return strlen(phrase) < CRYPT_MAX_PASSPHRASE_SIZE;
}
