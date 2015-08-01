#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "cbc.h"

// Polymorphic containers
struct cbc_parameters {
    void *context;
};
struct cbc_master_key {
    void *context;
};
struct cbc_secret_key {
    void *context;
};
struct cbc_public_index {
    void *context;
};
struct cbc_encrypted_payload {
    void *context;
};
struct cbc_input {
    void *context;
};
struct cbc_output {
    void *context;
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
dummySetup(void) 
{
    CBCParameters *parameters = (CBCParameters *) malloc(sizeof(CBCParameters));
    return NULL;
}

CBCMasterKey *
dummyCreateMasterKey(const CBCParameters *parameters) 
{
    return NULL;
}

CBCSecretKey *
dummyKeyGen(const CBCMasterKey *msk, const CBCPublicIndex *index) 
{
    return NULL;
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
