#include <cbc/crypto/primitives/hashing/cbc_Hasher.h>

struct cbc_hasher {
    CBCHasherType type;
    void *instance; // pointer to concrete instance, like SHA256 or SHA3
}

CBCHasher *
cbcHasher_Create(CBCHasherType type)
{
    return NULL;
}
