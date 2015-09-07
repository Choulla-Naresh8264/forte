#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
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
struct cbc_encrypted_payload {
    void *instance;
};
struct cbc_input {
    void *instance;
};
struct cbc_output {
    void *instance;
};

// Dummy containers
struct cbc_parameters_dummy {
    int x;
};
struct cbc_master_key_dummy {
    int x;
};
struct cbc_secret_key_dummy {
    int x;
};
struct cbc_public_index_dummy {
    int x;
};
struct cbc_encrypted_payload_dummy {
    int x;
};
struct cbc_input_dummy {
    int x;
};
struct cbc_output_dummy {
    int x;
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
struct cbc_encrypted_payload_rsa {
    uint8_t *payload;
    size_t length;
};
struct cbc_input_rsa {
    uint8_t *payload;
    size_t length;
};
struct cbc_output_rsa {
    uint8_t *payload;
    size_t length;
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
    int index;
};
struct cbc_public_index_bebgw {
    int index;
};
struct cbc_encrypted_payload_bebgw {
    element_t C0;
    element_t C1;
};
struct cbc_input_bebgw {
    uint8_t *payload;
    size_t length;
};
struct cbc_output_bebgw {
    uint8_t *payload;
    size_t length;
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

struct cbc_signing_scheme {
    void *instance;
    const CBCSignatureSchemeInterface *interface;
};

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

DummyInput *
dummyCreateInput(int val)
{
    DummyInput *di = (DummyInput *) malloc(sizeof(DummyInput));
    di->x = val;
    return di;
}

DummySecretKey *
dummyKeyGen(DummyEncryptionScheme *scheme, const DummyMasterKey *msk, const DummyPublicIndex *index)
{
    DummySecretKey *dummy = (DummySecretKey *) malloc(sizeof(DummySecretKey));
    dummy->x = msk->x + index->x;
    return dummy;
}

DummyEncryptedPayload *
dummyEncrypt(DummyEncryptionScheme *scheme, const DummyParameters *params, const DummyInput *input)
{
    DummyEncryptedPayload *enc = (DummyEncryptedPayload *) malloc(sizeof(DummyEncryptedPayload));
    enc->x = params->x + input->x;
    return enc;
}

DummyOutput *
dummyDecrypt(DummyEncryptionScheme *scheme, const DummySecretKey *sk, const DummyEncryptedPayload *payload)
{
    DummyOutput *dout = (DummyOutput *) malloc(sizeof(DummyOutput));
    dout->x = sk->x + payload->x;
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
rsaDisplay(RSAOutput *output)
{
    for (size_t i = 0; i < output->length; i++) {
        printf("%x", output->payload[i]);
    }
    printf("\n");
}

void
rsaDisplayCiphertext(RSAEncryptedPayload *output)
{
    for (size_t i = 0; i < output->length; i++) {
        printf("%x", output->payload[i]);
    }
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

RSAInput *
rsaCreateInput(size_t length, uint8_t input[length])
{
    RSAInput *rsaInput = (RSAInput *) malloc(sizeof(RSAInput));
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

RSAEncryptedPayload *
rsaEncrypt(RSAEncryptionScheme *scheme, const RSAParameters *params, const RSAInput *input)
{
    RSAEncryptedPayload *ct = (RSAEncryptedPayload *) malloc(sizeof(RSAEncryptedPayload));

    size_t size = RSA_size(params->publicRSA);
    ct->length = size;
    ct->payload = (uint8_t *) malloc(size);
    memset(ct->payload, 0, size);

    int padding = RSA_PKCS1_PADDING;
    int result = RSA_public_encrypt(input->length, input->payload, ct->payload, params->publicRSA, padding);

    return ct;
}

RSAOutput *
rsaDecrypt(RSAEncryptionScheme *scheme, const RSASecretKey *sk, const RSAEncryptedPayload *payload)
{
    RSAOutput *pt = (RSAOutput *) malloc(sizeof(RSAOutput));

    size_t size = RSA_size(sk->privateRSA);
    pt->length = size;
    pt->payload = (uint8_t *) malloc(size);
    memset(pt->payload, 0, size);

    int padding = RSA_PKCS1_PADDING;
    int result = RSA_private_decrypt(payload->length, payload->payload, pt->payload, sk->privateRSA, padding);

    return pt;
}

BEBGWEncryptionScheme *
bebgwCreate(size_t groupSize, char *pairFileName)
{
    BEBGWEncryptionScheme *scheme = (BEBGWEncryptionScheme *) malloc(sizeof(BEBGWEncryptionScheme));

    scheme->params = rsaSetup(publicFile);
    scheme->msk = rsaCreateMasterKey(scheme, scheme->params, privateFile);

    return scheme;
}

BEBGWParameters *
bebgwSetup(size_t groupSize, char *pairFileName)
{
    BEBGWParameters *params = (BEBGWParameters *) malloc(sizeof(BEBGWParameters));

    // Setup curve in gbp
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

    element_init_Zr(msk->privateKey, params->->pairing);
    element_random(msk->privateKey);

    element_init(msk->publicKey, params->pairing->G1);
    element_pow_zn(msk->publicKey, params->g, msk->privateKey);

    return msk;
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

CBCInput *
cbcInput_Create(void *instance)
{
    CBCInput *input = (CBCInput *) malloc(sizeof(CBCInput));
    input->instance = instance;
    return input;
}

CBCEncryptedPayload *
cbcEncryptedPayload_Create(void *instance)
{
    CBCEncryptedPayload *payload = (CBCEncryptedPayload *) malloc(sizeof(CBCEncryptedPayload));
    payload->instance = instance;
    return payload;
}

CBCOutput *
cbcOutput_Create(void *instance)
{
    CBCOutput *output = (CBCOutput *) malloc(sizeof(CBCOutput));
    output->instance = instance;
    return output;
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

CBCEncryptedPayload *
cbcEncrypt(CBCEncryptionScheme *scheme, const CBCParameters *params, const CBCInput *input)
{
    return (scheme->interface->Encrypt(scheme->instance, params->instance, input->instance));
}

CBCOutput *
cbcDecrypt(CBCEncryptionScheme *scheme, const CBCSecretKey *secretKey, const CBCEncryptedPayload *encryptedPayload)
{
    return (scheme->interface->Decrypt(scheme->instance, secretKey->instance, encryptedPayload->instance));
}
