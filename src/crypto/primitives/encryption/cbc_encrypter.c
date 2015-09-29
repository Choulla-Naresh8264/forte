#include <cbc/crypto/primitives/encryption/cbc_encrypter.h>
#include <cbc/crypto/string/cbc_string.h>

#include <openssl/pem.h>
#include <openssl/rand.h>

struct cbc_parameters {
    void *instance;
};
struct cbc_master_key {
    void *instance;
};
struct cbc_secret_key {
    void *instance;
};
struct cbc_public_index {
    void *instance;
};
struct cbc_ciphertext {
    void *instance;
};

struct cbc_encryption_scheme {
    void *instance;
    const CBCEncryptionSchemeInterface *interface;
};


CBCString *
encrypt(CBCString *input, uint8_t *key, uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        // TODO: throw exception
        return NULL;
    }

    int result = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (result != 1) {
        // TODO: throw exception
        return NULL;
    }

    int len;
    int ciphertext_len;
    CBCString *ciphertext = (CBCString *) malloc(sizeof(CBCString));
    ciphertext->payload = (uint8_t *) malloc(input->length + 16);

    result = EVP_EncryptUpdate(ctx, ciphertext->payload, &len, input->payload, input->length);
    if (result != 1) {
        // TODO: throw exception
        return NULL;
    }
    ciphertext->length = len;

    result = EVP_EncryptFinal_ex(ctx, ciphertext->payload + len, &len);
    if (result != 1) {
        // TODO: throw exception
        return NULL;
    }
    ciphertext->length += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext;
}

CBCString *
decrypt(CBCString *ciphertext, uint8_t *key, uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        // TODO: throw exception
        return NULL;
    }

    int result = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (result != 1) {
        // TODO;
        return NULL;
    }

    CBCString *plaintext = (CBCString *) malloc(sizeof(CBCString));
    plaintext->payload = (uint8_t *) malloc(ciphertext->length);

    int len;
    int plaintext_len;
    result = EVP_DecryptUpdate(ctx, plaintext->payload, &len, ciphertext->payload, ciphertext->length);
    if (result != 1) {
        // TODO: free
        return NULL;
    }
    plaintext->length = len;

    result = EVP_DecryptFinal_ex(ctx, plaintext->payload + len, &len);
    if (result != 1) {
        // TODO
        return NULL;
    }

    plaintext->length += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

CBCEncryptionScheme *
cbcEncryptionScheme(void *instance, CBCEncryptionSchemeInterface *interface)
{
    CBCEncryptionScheme *scheme = (CBCEncryptionScheme *) malloc(sizeof(CBCEncryptionScheme));
    scheme->instance = instance;
    scheme->interface = interface;
    return scheme;
}

CBCParameters *
cbcParameters_Create(void *instance)
{
    CBCParameters *params = (CBCParameters *) malloc(sizeof(CBCParameters));
    params->instance = instance;
    return params;
}

CBCMasterKey *
cbcMasterKey_Create(void *instance)
{
    CBCMasterKey *msk = (CBCMasterKey *) malloc(sizeof(CBCMasterKey));
    msk->instance = instance;
    return msk;
}

CBCSecretKey *
cbcSecretKey_Create(void *instance)
{
    CBCSecretKey *sk = (CBCSecretKey *) malloc(sizeof(CBCSecretKey));
    sk->instance = instance;
    return sk;
}

CBCCiphertext *
cbcCiphertext_Create(void *instance)
{
    CBCCiphertext *payload = (CBCCiphertext *) malloc(sizeof(CBCCiphertext));
    payload->instance = instance;
    return payload;
}

CBCPublicIndex *
cbcPublicIndex_Create(void *instance)
{
    CBCPublicIndex *index = (CBCPublicIndex *) malloc(sizeof(CBCPublicIndex));
    index->instance = instance;
    return index;
}

CBCMasterKey *
cbcGenerateMasterKey(CBCEncryptionScheme *scheme, const CBCParameters *parameters)
{
    return (scheme->interface->GenerateMasterKey(scheme->instance, parameters->instance));
}

CBCSecretKey *
cbcGenerateSecretKey(CBCEncryptionScheme *scheme, const CBCMasterKey *masterKey, const CBCPublicIndex *index)
{
    return (scheme->interface->GeneratePrivateKey(scheme->instance, masterKey->instance, index->instance));
}

CBCCiphertext *
cbcEncrypt(CBCEncryptionScheme *scheme, const CBCParameters *params, const CBCString *input, const void *metadata)
{
    return (scheme->interface->Encrypt(scheme->instance, params->instance, input, metadata));
}

CBCString *
cbcDecrypt(CBCEncryptionScheme *scheme, const CBCSecretKey *secretKey, const CBCCiphertext *encryptedPayload)
{
    return (scheme->interface->Decrypt(scheme->instance, secretKey->instance, encryptedPayload->instance));
}
