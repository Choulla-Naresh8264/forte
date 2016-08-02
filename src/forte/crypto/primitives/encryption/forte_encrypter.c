#include <forte/crypto/primitives/encryption/forte_encrypter.h>
#include <forte/string/forte_string.h>

#include <openssl/pem.h>
#include <openssl/rand.h>

struct forte_parameters {
    void *instance;
};
struct forte_master_key {
    void *instance;
};
struct forte_secret_key {
    void *instance;
};
struct forte_public_index {
    void *instance;
};
struct forte_ciphertext {
    void *instance;
};

struct forte_encryption_scheme {
    void *instance;
    const ForteEncryptorInterface *interface;
};


ForteString *
encrypt(ForteString *input, uint8_t *key, uint8_t *iv)
{
    // TODO: run the AES encryption algorithm

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        // TODO: throw exception
        return NULL;
    }

    int result = EVP_EncryptInit_ex(ctx, EVP_aes_256_forteEncryption(), NULL, key, iv);
    if (result != 1) {
        // TODO: throw exception
        return NULL;
    }

    int len;
    int ciphertext_len;
    ForteString *ciphertext = (ForteString *) malloc(sizeof(ForteString));
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

ForteString *
decrypt(ForteString *ciphertext, uint8_t *key, uint8_t *iv)
{
    // TODO: run the decryption algorithm.


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        // TODO: throw exception
        return NULL;
    }

    int result = EVP_DecryptInit_ex(ctx, EVP_aes_256_forteEncryption(), NULL, key, iv);
    if (result != 1) {
        // TODO;
        return NULL;
    }

    ForteString *plaintext = (ForteString *) malloc(sizeof(ForteString));
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

ForteEncryptionScheme *
forteEncryptionScheme(void *instance, ForteEncryptorInterface *interface)
{
    ForteEncryptionScheme *scheme = (ForteEncryptionScheme *) malloc(sizeof(ForteEncryptionScheme));
    scheme->instance = instance;
    scheme->interface = interface;
    return scheme;
}

ForteEncryptionParameters *
forteEncryptionParameters_Create(void *instance)
{
    ForteEncryptionParameters *params = (ForteEncryptionParameters *) malloc(sizeof(ForteEncryptionParameters));
    params->instance = instance;
    return params;
}

ForteEncryptionMasterKey *
forteEncryptionMasterKey_Create(void *instance)
{
    ForteEncryptionMasterKey *msk = (ForteEncryptionMasterKey *) malloc(sizeof(ForteEncryptionMasterKey));
    msk->instance = instance;
    return msk;
}

ForteEncryptionSecretKey *
forteEncryptionSecretKey_Create(void *instance)
{
    ForteEncryptionSecretKey *sk = (ForteEncryptionSecretKey *) malloc(sizeof(ForteEncryptionSecretKey));
    sk->instance = instance;
    return sk;
}

ForteEncryptionCiphertext *
forteEncryptionCiphertext_Create(void *instance)
{
    ForteEncryptionCiphertext *payload = (ForteEncryptionCiphertext *) malloc(sizeof(ForteEncryptionCiphertext));
    payload->instance = instance;
    return payload;
}

ForteEncryptionPublicIndex *
forteEncryptionPublicIndex_Create(void *instance)
{
    ForteEncryptionPublicIndex *index = (ForteEncryptionPublicIndex *) malloc(sizeof(ForteEncryptionPublicIndex));
    index->instance = instance;
    return index;
}

ForteEncryptionMasterKey *
forteEncryptionGenerateMasterKey(ForteEncryptionScheme *scheme, const ForteEncryptionParameters *parameters)
{
    return (scheme->interface->GenerateMasterKey(scheme->instance, parameters->instance));
}

ForteEncryptionSecretKey *
forteEncryptionGenerateSecretKey(ForteEncryptionScheme *scheme, const ForteEncryptionMasterKey *masterKey, const ForteEncryptionPublicIndex *index)
{
    return (scheme->interface->GeneratePrivateKey(scheme->instance, masterKey->instance, index->instance));
}

ForteEncryptionCiphertext *
forteEncryptionEncrypt(ForteEncryptionScheme *scheme, const ForteEncryptionParameters *params, const ForteString *input, const void *metadata)
{
    return (scheme->interface->Encrypt(scheme->instance, params->instance, input, metadata));
}

ForteString *
forteEncryptionDecrypt(ForteEncryptionScheme *scheme, const ForteEncryptionSecretKey *secretKey, const ForteEncryptionCiphertext *encryptedPayload)
{
    return (scheme->interface->Decrypt(scheme->instance, secretKey->instance, encryptedPayload->instance));
}
