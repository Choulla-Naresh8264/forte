#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <openssl/rsa.h>

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
// http://hayageek.com/rsa-encryption-decryption-openssl-c/
struct cbc_parameters_rsa {
    int x;
};
struct cbc_master_key_rsa {
    int x;
};
struct cbc_secret_key_rsa {
    int x;
};
struct cbc_public_index_rsa {
    int x;
};
struct cbc_encrypted_payload_rsa {
    int x;
};
struct cbc_input_rsa {
    int x;
};
struct cbc_output_rsa {
    int x;
};

struct cbc_encryption_scheme {
    void *instance;
    const CBCEncryptionSchemeInterface *interface;
};

struct cbc_encryption_scheme_dummy {
    DummyParameters *params;
    DummyMasterKey *msk;
};

struct cbc_encryption_scheme_rsa {
    RSA *rsaContext;
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

static RSA *
_generateRSAFromFile(char *fileName)
{
    FILE * fp = fopen(filename,"rb");
    if (fp == NULL) {
        printf("Unable to open file %s \n",filename);
        return NULL;    
    }

    RSA *rsa= RSA_new();

    if (password == NULL || strlen(password) == 0) {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    }

    return rsa;
}

RSAEncryptionScheme *
rsaCreate(char *publicFile, char *privateFile)
{
    RSAEncryptionScheme *scheme = (RSAEncryptionScheme *) malloc(sizeof(RSAEncryptionScheme));
    scheme->rsaContext = _generateRSAFromFile(fileName, password);
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

