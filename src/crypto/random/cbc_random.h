#ifndef cbc_random_h_
#define cbc_random_h_

#include <cbc/strings/cbc_string.h>

struct cbc_random;
typedef struct cbc_random CBCRandom;

CBCRandom *cbcRandom_Create();
CBCRandom *cbcRandom_CreateWithSeed(CBCString *seed);
CBCRandom *cbcRandom_SetSeed(CBCRandom *random, CBCString *seed);
CBCString *cbcRandom_GetRandomBits(CBCRandom *random, size_t numBits);
CBCString *cbcRandom_GetRandomBytes(CBCRandom *random, size_t numBytes);

uint32_t cbcRandom_GetRandomUint32(CBCRandom *random);
uint64_t cbcRandom_GetRandomUint64(CBCRandom *random);
uint8_t cbcRandom_GetRandomUint8(CBCRandom *random);
uint8_t cbcRandom_GetRandomByte(CBCRandom *random);

#endif // cbc_random_h_
