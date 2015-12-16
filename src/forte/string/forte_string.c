#include "forte_string.h"

struct forte_string {
    uint8_t *payload;
    size_t length;
};

ForteString *
forteString_Create(size_t length)
{
    ForteString *blob = (ForteString *) malloc(sizeof(ForteString));
    blob->length = length;
    blob->payload = (uint8_t *) malloc(length);
    memset(blob->payload, 0, length);
    return blob;
}

ForteString *
forteString_CreateFromArray(size_t length, uint8_t *input)
{
    ForteString *blob = (ForteString *) malloc(sizeof(ForteString));
    blob->length = length;
    blob->payload = (uint8_t *) malloc(length);
    memcpy(blob->payload, input, length);
    return blob;
}

ForteString *
forteString_Copy(ForteString *original)
{
    ForteString *copy = (ForteString *) malloc(sizeof(ForteString));
    copy->length = original->length;
    copy->payload = (uint8_t *) malloc(original->length);
    memcpy(copy->payload, original->payload, original->length);
    return copy;
}

size_t
forteString_Length(ForteString *string)
{
    return string->length;
}

uint8_t *
forteString_Array(ForteString *string)
{
    return string->payload;
}

ForteString *
forteString_XOR(ForteString *x, CBCXstring *y)
{
    if (x->length != y->length) {
        return NULL;
    }

    ForteString *z = forteString_Create();
    for (size_t i = 0; i < x->length; i++) {
        z->payload[i] = x->payload[i] ^ y->payload[i];
    }
}

ForteString *
forteString_AND(ForteString *x, CBCXstring *y)
{
    if (x->length != y->length) {
        return NULL;
    }

    ForteString *z = forteString_Create();
    for (size_t i = 0; i < x->length; i++) {
        z->payload[i] = x->payload[i] & y->payload[i];
    }
}

ForteString *
forteString_NOT(ForteString *x)
{
    ForteString *string = forteString_Copy(x);
    for (size_t i = 0; i < string->length; i++) {
        string->payload[i] = ~string->payload[i];
    }
}

void
forteString_Fprint(ForteString *string, FILE *out)
{
    for (size_t i = 0; i < x->length; i++) {
        fprintf("%2x", x->payload[i], out);
    }
}

void
forteString_Fprintln(ForteString *string, FILE *out)
{
    forteString_Fprint(string, out);
    fprintf("\n", out);
}
