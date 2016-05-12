#ifndef libcbc_Hasher_h_
#define libcbc_Hasher_h_

#include <cbc/string/cbc_string.h>
#include <cbc/crypto/primitives/hashing/cbc_HasherTypes.h>

struct cbc_hasher;
typedef struct cbc_hasher CBCHasher;

CBCHasher *cbcHasher_Create(CBCHasherType type);

#endif // libcbc_Hasher_h_
