#include <cbc/crypto/primitives/encryption/cbc_encrypter.h>
#include <cbc/crypto/primitives/encryption/internal/cbc_rsa.h>

RSAParameters *
rsaSetup(char *publicKeyPemFile)
{
    RSAParameters *params = (RSAParameters *) malloc(sizeof(RSAParameters));

    FILE *fp = fopen(publicKeyPemFile, "rb");
    if(fp == NULL) {
        printf("Unable to open file %s \n", publicKeyPemFile);
        return NULL;
    }

    params->publicRSA = RSA_new();
    params->publicRSA = PEM_read_RSA_PUBKEY(fp, &params->publicRSA, NULL, NULL);

    return params;
}

RSAParameters *
rsaGetParameters(RSAEncryptionScheme *scheme)
{
    return scheme->params;
}

RSAMasterKey *
rsaGetMasterKey(RSAEncryptionScheme *scheme)
{
    return scheme->msk;
}

RSAMasterKey *
rsaCreateMasterKey(RSAEncryptionScheme *scheme, const RSAParameters *parameters, char *privateKeyPemFile)
{
    RSAMasterKey *msk = (RSAMasterKey *) malloc(sizeof(RSAMasterKey));

    FILE *fp = fopen(privateKeyPemFile, "rb");
    if(fp == NULL) {
        printf("Unable to open file %s \n", privateKeyPemFile);
        return NULL;
    }

    msk->publicRSA = parameters->publicRSA;
    msk->privateRSA = RSA_new();
    msk->privateRSA = PEM_read_RSAPrivateKey(fp, &msk->privateRSA, NULL, NULL);

    return msk;
}

RSAEncryptionScheme *
rsaCreate(char *publicFile, char *privateFile)
{
    RSAEncryptionScheme *scheme = (RSAEncryptionScheme *) malloc(sizeof(RSAEncryptionScheme));

    scheme->params = rsaSetup(publicFile);
    scheme->msk = rsaCreateMasterKey(scheme, scheme->params, privateFile);

    return scheme;
}

RSAPublicIndex *
rsaCreatePublicIndex(RSAEncryptionScheme *scheme)
{
    RSAPublicIndex *index = (RSAParameters *) malloc(sizeof(RSAPublicIndex));

    index->publicRSA = scheme->params->publicRSA;

    return index;
}

RSASecretKey *
rsaKeyGen(RSAEncryptionScheme *scheme)
{
    RSASecretKey *sk = (RSASecretKey *) malloc(sizeof(RSASecretKey));
    sk->privateRSA = scheme->msk->privateRSA;
    return sk;
}

RSACiphertext *
rsaEncrypt(RSAEncryptionScheme *scheme, const RSAParameters *params, const CBCString *input)
{
    RSACiphertext *ct = (RSACiphertext *) malloc(sizeof(RSACiphertext));

    size_t size = RSA_size(params->publicRSA) / 2;

    // Create the symmetric key to be encrypted by RSA
    ct->keyBlob = (CBCString *) malloc(sizeof(CBCString));
    uint8_t *symmetricKey = (uint8_t *) malloc(size);
    ct->keyBlob->payload = (uint8_t *) malloc(size * 2);
    ct->iv = (uint8_t *) malloc(size);
    int result = RAND_bytes(symmetricKey, size);
    if (result != 1) {
        // TODO: free
        return NULL;
    }
    result = RAND_bytes(ct->iv, size);
    if (result != 1) {
        // TODO: free
        return NULL;
    }

    // encrypt the input with the symmetric key and IV
    CBCString *ciphertext = encrypt(input, symmetricKey, ct->iv);

    // Allocate space for the ciphertext and store it
    ct->dataBlob = (CBCString *) malloc(sizeof(CBCString));
    ct->dataBlob->length = ciphertext->length;
    ct->dataBlob->payload = (uint8_t *) malloc(ciphertext->length);
    memcpy(ct->dataBlob->payload, ciphertext->payload, ciphertext->length);

    // encrypt the symmetric key with RSA
    int padding = RSA_PKCS1_PADDING;
    int bytesEncrypted = RSA_public_encrypt(size, symmetricKey, ct->keyBlob->payload, params->publicRSA, padding);
    if (bytesEncrypted == -1) {
        // TODO: free
        printf("failed: %lu\n", ERR_get_error());
        return NULL;
    }
    ct->keyBlob->length = bytesEncrypted;

    return ct;
}

CBCString *
rsaDecrypt(RSAParameters *params, const RSASecretKey *sk, const RSACiphertext *payload)
{
    CBCString *pt = (CBCString *) malloc(sizeof(CBCString));

    size_t size = RSA_size(sk->privateRSA) / 2;
    pt->length = size;
    pt->payload = (uint8_t *) malloc(size);
    memset(pt->payload, 0, size);

    uint8_t *key = (uint8_t *) malloc(size * 2);

    int padding = RSA_PKCS1_PADDING;
    int result = RSA_private_decrypt(payload->keyBlob->length, payload->keyBlob->payload, key, sk->privateRSA, padding);
    if (result == -1) {
        printf("Failure %lu\n", ERR_get_error());
        return NULL;
    }

    CBCString *plaintext = decrypt(payload->dataBlob, key, payload->iv);

    return plaintext;
}
