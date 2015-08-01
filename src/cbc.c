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
    const CBCEncryptionScheme *interface;
}

struct cbc_signing_scheme {
    void *instance;
    const CBCSignatureScheme *interface;
}

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
dummyCreateMasterKey(const CBCParameters *parameters) 
{
    CBCMasterKey *masterKey = (CBCMasterKey *) malloc(sizeof(CBCMasterKey));
    
    DummyMasterKey *dummy = (DummyMasterKey *) malloc(sizeof(DummyMasterKey));
    DummyParameters *params = (DummyParameters *) parameters->instance;
    dummy->x = params->x + 1;
    masterKey->instance = dummy;

    return masterKey;
}

CBCSecretKey *
dummyKeyGen(const CBCMasterKey *msk, const CBCPublicIndex *index) 
{
    CBCSecretKeys *secretKey = (CBCSecretKeys *) malloc(sizeof(CBCSecretKeys));
    
    DummySecretKey *dummy = (DummySecretKey *) malloc(sizeof(DummySecretKey));
    DummyMasterKey *master = (DummyMasterKey *) msk->instance;
    DummyPublicIndex *pindex = (DummyPublicIndex *) index->instance;
    dummy->x = master->x + pindex->x;
    secretKey->instance = dummy;

    return secretKey;
}

CBCEncryptedPayload *
dummyEncrypt(const CBCParameters *params, const CBCInput *input)
{
    return NULL;
}

CBCOutput *
dummyDecrypt(const CBCSecretKey *sk, const CBCEncryptedPayload *payload)
{
    return NULL;
}

CBCEncryptionScheme *CBCEncryptionSchemeBE = &(CBCEncryptionScheme) {
    .Setup = (CBCParameters * (*)(void)) dummySetup,
    .GenerateMasterKey = (CBCMasterKey * (*)(const CBCParameters *)) dummyCreateMasterKey,
    .GeneratePrivateKey = (CBCSecretKey * (*)(const CBCMasterKey *, const CBCPublicIndex *)) dummyKeyGen,
    .Encrypt = (CBCEncryptedPayload * (*)(const CBCParameters *, const CBCInput *)) dummyEncrypt,
    .Decrypt = (CBCOutput * (*)(const CBCSecretKey *, const CBCEncryptedPayload *)) dummyDecrypt,
};
