#include <cbc/random/cbc_random.h>

CBCString *
cbcRandom_GetRandomBytes(size_t numBytes)
{
    CBCString *string = cbcString_Create(numBytes);

    // TODO: populate the payload with bytes

    return string;
}
