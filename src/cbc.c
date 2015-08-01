#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "cbc.h"

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

struct cbc_encryption_scheme {
    void *instance;
    const CBCEncryptionSchemeInterface *interface;
};

struct cbc_signing_scheme {
    void *instance;
    const CBCSignatureSchemeInterface *interface;
};

// Dummy functions 
CBCParameters *
dummySetup(int initial) 
{
    CBCParameters *parameters = (CBCParameters *) malloc(sizeof(CBCParameters));

    DummyParameters *dummy = (DummyParameters *) malloc(sizeof(DummyParameters));
    dummy->x = initial;
    parameters->instance = dummy;

    return parameters;
}

CBCMasterKey *
dummyCreateMasterKey(void *scheme, const CBCParameters *parameters) 
{
    CBCMasterKey *masterKey = (CBCMasterKey *) malloc(sizeof(CBCMasterKey));
    
    DummyMasterKey *dummy = (DummyMasterKey *) malloc(sizeof(DummyMasterKey));
    DummyParameters *params = (DummyParameters *) parameters->instance;
    dummy->x = params->x + 1;
    masterKey->instance = dummy;

    return masterKey;
}

// This function is specific to each scheme, and not part of the CBC interface
CBCPublicIndex *
dummyCreatePublicIndex(int val)
{
    CBCPublicIndex *index = (CBCPublicIndex *) malloc(sizeof(CBCPublicIndex));
    DummyPublicIndex *pindex = (DummyPublicIndex *) malloc(sizeof(DummyPublicIndex));
    index->instance = pindex;
    pindex->x = val;
    return index;
}

CBCInput *
dummyCreateInput(int val)
{
    CBCInput *input = (CBCInput *) malloc(sizeof(CBCInput));
    DummyInput *di = (DummyInput *) malloc(sizeof(DummyInput));
    di->x = val;
    input->instance = di;
    return input;
}

CBCSecretKey *
dummyKeyGen(void *scheme, const CBCMasterKey *msk, const CBCPublicIndex *index) 
{
    CBCSecretKey *secretKey = (CBCSecretKey *) malloc(sizeof(CBCSecretKey));
    
    DummySecretKey *dummy = (DummySecretKey *) malloc(sizeof(DummySecretKey));
    DummyMasterKey *master = (DummyMasterKey *) msk->instance;
    DummyPublicIndex *pindex = (DummyPublicIndex *) index->instance;
    dummy->x = master->x + pindex->x;
    secretKey->instance = dummy;

    return secretKey;
}

CBCEncryptedPayload *
dummyEncrypt(void *scheme, const CBCParameters *params, const CBCInput *input)
{
    CBCEncryptedPayload *payload = (CBCEncryptedPayload *) malloc(sizeof(CBCEncryptedPayload));

    DummyEncryptedPayload *enc = (DummyEncryptedPayload *) malloc(sizeof(DummyEncryptedPayload));
    DummyParameters *dp = (DummyParameters *) params->instance;
    DummyInput *di = (DummyInput *) input->instance;

    enc->x = dp->x + di->x;
    payload->instance = enc;

    return payload;
}

CBCOutput *
dummyDecrypt(void *scheme, const CBCSecretKey *sk, const CBCEncryptedPayload *payload)
{
    CBCOutput *output = (CBCOutput *) malloc(sizeof(CBCOutput));

    DummySecretKey *dk = (DummySecretKey *) sk->instance;
    DummyEncryptedPayload *dp = (DummyEncryptedPayload *) payload->instance;
    DummyOutput *dout = (DummyOutput *) malloc(sizeof(DummyOutput));
    dout->x = dk->x + dp->x;

    output->instance = dout;

    return output;
}

CBCEncryptionSchemeInterface *CBCEncryptionSchemeDummy = &(CBCEncryptionSchemeInterface) {
    .GenerateMasterKey = (CBCMasterKey * (*)(void *scheme, const void *)) dummyCreateMasterKey,
    .GeneratePrivateKey = (CBCSecretKey * (*)(void *scheme, const void *, const void *)) dummyKeyGen,
    .Encrypt = (CBCEncryptedPayload * (*)(void *scheme, const void *, const void *)) dummyEncrypt,
    .Decrypt = (CBCOutput * (*)(void *scheme, const void *, const void *)) dummyDecrypt,
};

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

