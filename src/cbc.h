#ifndef libcbc_h_
#define libcbc_h_

#include <stdint.h>
#include <stddef.h>

struct cbc_blob;
typedef struct cbc_blob CBCBlob;

CBCBlob *createBlob(size_t length, uint8_t input[length]);
void blobDisplay(CBCBlob *output);

#endif /* libcbc_h_ */
