#include <cbc/string/cbc_string.h>

struct cbc_string {
    uint8_t *payload;
    size_t length;
};

CBCString *
cbcString_Create(size_t length)
{
    CBCString *blob = (CBCString *) malloc(sizeof(CBCString));
    blob->length = length;
    blob->payload = (uint8_t *) malloc(length);
    memset(blob->payload, 0, length);
    return blob;
}

CBCString *
cbcString_CreateFromArray(size_t length, uint8_t input[length])
{
    CBCString *blob = (CBCString *) malloc(sizeof(CBCString));
    blob->length = length;
    blob->payload = (uint8_t *) malloc(length);
    memcpy(blob->payload, input, length);
    return blob;
}

CBCString *
cbcString_Copy(CBCString *original)
{
    CBCString *copy = (CBCString *) malloc(sizeof(CBCString));
    copy->length = original->length;
    copy->payload = (uint8_t *) malloc(original->length);
    memcpy(copy->payload, original->payload, original->length);
    return copy;
}

size_t
cbcString_Length(CBCString *string)
{
    return string->length;
}

uint8_t *
cbcString_Array(CBCString *string)
{
    return string->payload;
}

CBCString *
cbcString_XOR(CBCString *x, CBCXstring *y)
{
    if (x->length != y->length) {
        return NULL;
    }

    CBCString *z = cbcString_Create();
    for (size_t i = 0; i < x->length; i++) {
        z->payload[i] = x->payload[i] ^ y->payload[i];
    }
}

CBCString *
cbcString_AND(CBCString *x, CBCXstring *y)
{
    if (x->length != y->length) {
        return NULL;
    }

    CBCString *z = cbcString_Create();
    for (size_t i = 0; i < x->length; i++) {
        z->payload[i] = x->payload[i] & y->payload[i];
    }
}

CBCString *
cbcString_NOT(CBCString *x)
{
    CBCString *string = cbcString_Copy(x);
    for (size_t i = 0; i < string->length; i++) {
        string->payload[i] = ~string->payload[i];
    }
}

void
cbcString_Fprint(CBCString *string, FILE *out)
{
    for (size_t i = 0; i < x->length; i++) {
        fprintf("%2x", x->payload[i], out);
    }
}

void
cbcString_Fprintln(CBCString *string, FILE *out)
{
    cbcString_Fprint(string, out);
    fprintf("\n", out);
}
