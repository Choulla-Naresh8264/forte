#ifndef cbc_string_h_
#define cbc_string_h_

struct cbc_string;
typedef struct cbc_string CBCString;

CBCString *cbcString_Create(size_t length);
CBCString *cbcString_CreateFromArray(size_t length, uint8_t input[length]);
CBCString *cbcString_Copy(CBCString *original);

size_t cbcString_Length(CBCString *string);
uint8_t *cbcString_Array(CBCString *string);

CBCString *cbcString_XOR(CBCString *stringX, CBCXstring *stringY);
CBCString *cbcString_AND(CBCString *stringX, CBCXstring *stringY);
CBCString *cbcString_NOT(CBCString *string);
void cbcString_Fprint(CBCString *string, FILE *out);
void cbcString_Fprintln(CBCString *string, FILE *out);

#endif // cbc_string_h_
