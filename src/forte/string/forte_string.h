#ifndef forte_string_h_
#define forte_string_h_

#include <stdio.h>
#include <forte.h>

struct forte_string;
typedef struct forte_string ForteString;

ForteString *forteString_Create(size_t length);
ForteString *forteString_CreateFromArray(size_t length, uint8_t *input);
ForteString *forteString_Copy(ForteString *original);

size_t forteString_Length(ForteString *string);
uint8_t *forteString_Array(ForteString *string);

ForteString *forteString_XOR(ForteString *stringX, ForteString *stringY);
ForteString *forteString_AND(ForteString *stringX, ForteString *stringY);
ForteString *forteString_NOT(ForteString *string);
void forteString_Fprint(ForteString *string, FILE *out);
void forteString_Fprintln(ForteString *string, FILE *out);

#endif // forte_string_h_
