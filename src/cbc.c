#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <pbc.h>

#include "cbc.h"

// Encoding container
struct cbc_encoded_value {
    uint8_t *data;
    size_t length;
};

// Polymorphic containers
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
struct cbc_blob {
    uint8_t *payload;
    size_t length;
};

// Dummy containers
struct cbc_parameters_dummy {
    size_t x;
};
struct cbc_master_key_dummy {
    size_t x;
};
struct cbc_secret_key_dummy {
    size_t x;
};
struct cbc_public_index_dummy {
    size_t x;
};
struct cbc_ciphertext_dummy {
    size_t x;
};

// RSA containers
struct cbc_parameters_rsa {
    RSA *publicRSA;
};
struct cbc_master_key_rsa {
    RSA *publicRSA;
    RSA *privateRSA;
};
struct cbc_secret_key_rsa {
    RSA *privateRSA;
};
struct cbc_public_index_rsa {
    RSA *publicRSA;
};
struct cbc_ciphertext_rsa {
    CBCBlob *keyBlob;
    CBCBlob *dataBlob;
    uint8_t *iv;
};

// BE containers
struct cbc_parameters_bebgw {
    pairing_t pairing;
    char *pairFileName;
    element_t g;
    element_t h;
    element_t *gs;
    element_t *hs;
    int groupSize;
};
struct cbc_master_key_bebgw {
    element_t encryptionProduct;
    element_t publicKey;
    element_t privateKey;
};
struct cbc_secret_key_bebgw {
    element_t g_i_gamma;
    element_t g_i;
    element_t h_i;
    element_t decr_prod;
    size_t index;
};
struct cbc_public_index_bebgw {
    size_t index;
};
struct cbc_ciphertext_bebgw {
    // Header elements (used to derive encryption/decryption key)
    element_t C0;
    element_t C1;

    // The actual encrypted data
    CBCBlob payload;
};

struct cbc_encryption_scheme {
    void *instance;
    const CBCEncryptionSchemeInterface *interface;
};

struct cbc_encryption_scheme_dummy {
    int x;
    DummyParameters *params;
    DummyMasterKey *msk;
};

struct cbc_encryption_scheme_rsa {
    RSAParameters *params;
    RSAMasterKey *msk;
};

struct cbc_encryption_scheme_bebgw {
    BEBGWParameters *params;
    BEBGWMasterKey *msk;
};

struct cbc_signing_scheme {
    void *instance;
    const CBCSignatureSchemeInterface *interface;
};

CBCBlob *
encrypt(CBCBlob *input, uint8_t *key, uint8_t *iv)
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
    CBCBlob *ciphertext = (CBCBlob *) malloc(sizeof(CBCBlob));
    ciphertext->payload = (uint8_t *) malloc(input->length);

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

CBCBlob *
decrypt(CBCBlob *ciphertext, uint8_t *key, uint8_t *iv)
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

    CBCBlob *plaintext = (CBCBlob *) malloc(sizeof(CBCBlob));
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

DummyEncryptionScheme *
dummyCreate(int x)
{
    DummyEncryptionScheme *scheme = (DummyEncryptionScheme *) malloc(sizeof(DummyEncryptionScheme));
    scheme->x = x;
    return scheme;
}

// Dummy functions
DummyParameters *
dummySetup(int initial)
{
    DummyParameters *dummy = (DummyParameters *) malloc(sizeof(DummyParameters));
    dummy->x = initial;
    return dummy;
}

DummyMasterKey *
dummyCreateMasterKey(DummyEncryptionScheme *scheme, const DummyParameters *parameters)
{
    DummyMasterKey *dummy = (DummyMasterKey *) malloc(sizeof(DummyMasterKey));
    dummy->x = parameters->x + 1;
    return dummy;
}

// This function is specific to each scheme, and not part of the CBC interface
DummyPublicIndex *
dummyCreatePublicIndex(int val)
{
    DummyPublicIndex *pindex = (DummyPublicIndex *) malloc(sizeof(DummyPublicIndex));
    pindex->x = val;
    return pindex;
}

DummySecretKey *
dummyKeyGen(DummyEncryptionScheme *scheme, const DummyMasterKey *msk, const DummyPublicIndex *index)
{
    DummySecretKey *dummy = (DummySecretKey *) malloc(sizeof(DummySecretKey));
    dummy->x = msk->x + index->x;
    return dummy;
}

DummyCiphertext *
dummyEncrypt(DummyEncryptionScheme *scheme, const DummyParameters *params, const CBCBlob *input)
{
    DummyCiphertext *enc = (DummyCiphertext *) malloc(sizeof(DummyCiphertext));
    enc->x = input->length;
    return enc;
}

CBCBlob *
dummyDecrypt(DummyEncryptionScheme *scheme, const DummySecretKey *sk, const DummyCiphertext *payload)
{
    CBCBlob *dout = (CBCBlob *) malloc(sizeof(CBCBlob));
    dout->length = sk->x + payload->x;
    return dout;
}

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

void
blobDisplay(CBCBlob *output)
{
    for (size_t i = 0; i < output->length; i++) {
        printf("%x", output->payload[i]);
    }
    printf("\n");
}

void
rsaDisplay(RSACiphertext *ct) {
    blobDisplay(ct->keyBlob);
    printf("\n");
    blobDisplay(ct->dataBlob);
    printf("\n");
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

CBCBlob *
rsaCreateInput(size_t length, uint8_t input[length])
{
    CBCBlob *rsaInput = (CBCBlob *) malloc(sizeof(CBCBlob));
    rsaInput->length = length;
    rsaInput->payload = (uint8_t *) malloc(length);
    memcpy(rsaInput->payload, input, length);
    return rsaInput;
}

RSASecretKey *
rsaKeyGen(RSAEncryptionScheme *scheme)
{
    RSASecretKey *sk = (RSASecretKey *) malloc(sizeof(RSASecretKey));
    sk->privateRSA = scheme->msk->privateRSA;
    return sk;
}

RSACiphertext *
rsaEncrypt(RSAEncryptionScheme *scheme, const RSAParameters *params, const CBCBlob *input)
{
    RSACiphertext *ct = (RSACiphertext *) malloc(sizeof(RSACiphertext));

    size_t size = RSA_size(params->publicRSA) / 2;

    // Create the symmetric key to be encrypted by RSA
    ct->keyBlob = (CBCBlob *) malloc(sizeof(CBCBlob));
    uint8_t *symmetricKey = (uint8_t *) malloc(size);
    ct->keyBlob->payload = (uint8_t *) malloc(size * 2);
    ct->iv = (uint8_t *) malloc(size);
    int result = RAND_bytes(symmetricKey, size);
    if (result != 1) {
        // TODO: free
        return NULL;
    }

    // encrypt the input with the symmetric key and IV
    CBCBlob *ciphertext = encrypt(input, symmetricKey, ct->iv);

    // Allocate space for the ciphertext and store it
    ct->dataBlob = (CBCBlob *) malloc(sizeof(CBCBlob));
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

CBCBlob *
rsaDecrypt(RSAParameters *params, const RSASecretKey *sk, const RSACiphertext *payload)
{
    CBCBlob *pt = (CBCBlob *) malloc(sizeof(CBCBlob));

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

    CBCBlob *plaintext = decrypt(payload->dataBlob, key, payload->iv);

    return plaintext;
}

BEBGWParameters *
bebgwSetup(size_t groupSize, char *pairFileName)
{
    BEBGWParameters *params = (BEBGWParameters *) malloc(sizeof(BEBGWParameters));

    // Setup curve
    FILE *curveFile = fopen(pairFileName, "r");
    params->pairFileName = strdup(pairFileName);
    if(!curveFile) {
        printf("%s doesn't exist! exiting! \n\n", pairFileName);
        return NULL;
    }

    char s[1024];
    size_t count = fread(s, 1, 1024, curveFile);
    if (!count) {
        return NULL;
    }
    if (pairing_init_set_buf(params->pairing, s, count)) {
        printf("pairing init failed\n");
        return NULL;
    }
    fclose(curveFile);

    if (groupSize % 8 != 0) {
        printf("\nSystem size must be a multiple of 8\n");
        printf("Didn't finish system setup\n\n");
        return NULL;
    }

    params->groupSize = groupSize;
    element_t *lgs;
    element_t *lhs;
    int i;

    lgs = pbc_malloc(2 * groupSize * sizeof(element_t));
    lhs = pbc_malloc(2 * groupSize * sizeof(element_t));
    if (!(lhs) || !(lgs)) {
        printf("\nMalloc Failed\n");
        printf("Didn't finish system setup\n\n");
    }

    // Choosing random G & H
    element_init(params->g, params->pairing->G1);
    element_random(params->g);
    element_init(params->h, params->pairing->G2);
    element_random(params->h);

    // Pick a random exponent alpha
    element_t alpha;
    element_init_Zr(alpha, params->pairing);
    element_random(alpha);

    // Make the 0th elements equal to x^alpha
    element_init(lgs[0], params->pairing->G1);
    element_init(lhs[0], params->pairing->G2);
    element_pow_zn(lgs[0], params->g, alpha);
    element_pow_zn(lhs[0], params->h, alpha);

    // Fill in the gs and the hs arrays
    for(i = 1; i < 2 * groupSize; i++) {
        element_init(lgs[i], params->pairing->G1);
        element_pow_zn(lgs[i],lgs[i-1], alpha);
        element_init(lhs[i], params->pairing->G2);
        element_pow_zn(lhs[i], lhs[i-1], alpha);
        if (i == groupSize + 1) {
            element_clear(lgs[i-1]);
            element_clear(lhs[i-1]);
        }
    }

    // For simplicity & so code was easy to read
    params->gs = lgs;
    params->hs = lhs;

    element_clear(alpha);

    return params;
}

BEBGWMasterKey *
bebgwCreateMasterKey(BEBGWParameters *params)
{
    BEBGWMasterKey *msk = (BEBGWMasterKey *) malloc(sizeof(BEBGWMasterKey));

    element_init_Zr(msk->privateKey, params->pairing);
    element_random(msk->privateKey);

    element_init(msk->publicKey, params->pairing->G1);
    element_pow_zn(msk->publicKey, params->g, msk->privateKey);

    return msk;
}

BEBGWParameters *
bebgwGetParameters(BEBGWEncryptionScheme *scheme)
{
    return scheme->params;
}

BEBGWMasterKey *
bebgwGetMasterKey(BEBGWEncryptionScheme *scheme)
{
    return scheme->msk;
}

BEBGWSecretKey *
bebgwKeyGen(BEBGWEncryptionScheme *scheme, int index)
{
    BEBGWParameters *params = scheme->params;
    BEBGWMasterKey *msk = scheme->msk;

    BEBGWSecretKey *secretKey = (BEBGWSecretKey *) malloc(sizeof(BEBGWSecretKey));

    element_init(secretKey->g_i_gamma, params->pairing->G1);
    element_init(secretKey->g_i, params->pairing->G1);
    element_init(secretKey->h_i, params->pairing->G2);
    secretKey->index = index;
    element_set(secretKey->g_i, params->gs[index - 1]);
    element_set(secretKey->h_i, params->hs[index - 1]);
    element_pow_zn(secretKey->g_i_gamma, params->gs[index - 1], msk->privateKey);

    return secretKey;
}

BEBGWCiphertext *
bebgwEncrypt(BEBGWEncryptionScheme *scheme, const BEBGWParameters *params, const CBCBlob *input)
{
    BEBGWCiphertext *ct = (BEBGWCiphertext *) malloc(sizeof(BEBGWCiphertext));

    element_t t;
    element_init_Zr(t, params->pairing);
    element_random(t);

    element_t key; // the symmetric encryption key
    element_init(key, params->pairing->GT);
    element_init(ct->C0, params->pairing->G2);
    element_init(ct->C1, params->pairing->G1);

    // Compute K
    element_pairing(key, params->gs[params->groupSize - 1], params->hs[0]);
    element_pow_zn(key, key, t);

    // Compute C0
    element_pow_zn(ct->C0, params->h, t);

    // Compute C1
    element_mul(ct->C1, scheme->msk->publicKey, scheme->msk->encryptionProduct);
    element_pow_zn(ct->C1, ct->C1, t);
    element_clear(t);

    // TODO: encrypt payload of CT with symmetric key "key"

    return ct;
}

CBCBlob *
bebgwDecrypt(BEBGWParameters *params, const BEBGWSecretKey *sk, const BEBGWCiphertext *ciphertext)
{
    element_t temp;
    element_t temp2;
    element_t di_de;
    element_t temp3;

    CBCBlob *plaintext = (CBCBlob *) malloc(sizeof(CBCBlob));

    element_init(temp, params->pairing->GT);
    element_init(temp2, params->pairing->GT);
    element_init(di_de, params->pairing->G1);
    element_init(temp3, params->pairing->GT);

    // Generate the numerator
    element_pairing(temp, ciphertext->C1, sk->h_i);

    // G1 element in denom
    element_mul(di_de, sk->g_i_gamma, sk->decr_prod);

    // Generate the denominator
    element_pairing(temp2, di_de, ciphertext->C0);

    // Invert the denominator
    element_invert(temp3, temp2);

    element_t key;
    element_init(key, params->pairing->GT);

    // Multiply the numerator by the inverted denominator
    element_mul(key, temp, temp3);

    // TODO: we now have the key to decrypt the ciphertext

    return plaintext;
}

BEBGWEncryptionScheme *
bebgwCreate(size_t groupSize, char *pairFileName)
{
    BEBGWEncryptionScheme *scheme = (BEBGWEncryptionScheme *) malloc(sizeof(BEBGWEncryptionScheme));

    scheme->params = bebgwSetup(groupSize, pairFileName);
    scheme->msk = bebgwCreateMasterKey(scheme->params);

    return scheme;
}

CBCEncryptionSchemeInterface *CBCEncryptionSchemeDummy = &(CBCEncryptionSchemeInterface) {
    .GenerateMasterKey = (void * (*)(void *scheme, const void *)) dummyCreateMasterKey,
    .GeneratePrivateKey = (void * (*)(void *scheme, const void *, const void *)) dummyKeyGen,
    .Encrypt = (void * (*)(void *scheme, const void *, const void *)) dummyEncrypt,
    .Decrypt = (void * (*)(void *scheme, const void *, const void *)) dummyDecrypt,
};

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
cbcEncrypt(CBCEncryptionScheme *scheme, const CBCParameters *params, const CBCBlob *input)
{
    return (scheme->interface->Encrypt(scheme->instance, params->instance, input));
}

CBCBlob *
cbcDecrypt(CBCEncryptionScheme *scheme, const CBCSecretKey *secretKey, const CBCCiphertext *encryptedPayload)
{
    return (scheme->interface->Decrypt(scheme->instance, secretKey->instance, encryptedPayload->instance));
}
