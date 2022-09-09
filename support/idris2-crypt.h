char *idris_gensalt(const char *pre, unsigned long count);

char *idris_crypt(const char *salt, const char *phrase);

int idris_crypt_check(const char *key, const char *phrase);

int idris_checksalt(const char *salt);

int idris_checkphrase(const char *phrase);
