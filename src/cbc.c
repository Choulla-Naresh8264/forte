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
struct cbc_parameters_be {
    void *context;
};
struct cbc_master_key_be {
    void *context;
};
struct cbc_secret_key_be {
    void *context;
};
struct cbc_public_index_be {
    void *context;
};
struct cbc_encrypted_payload_be {
    void *context;
};
struct cbc_input_be {
    void *context;
};
struct cbc_output_be {
    void *context;
};

// Dummy functions 
CBCParameters *
beSetup(void) 
{
    CBCParameters *parameters = (CBCParameters *) malloc(sizeof(CBCParameters));
    return NULL;
}

CBCMasterKey *
beCreateMasterKey(const CBCParameters *parameters) 
{
    return NULL;
}

CBCSecretKey *
beKeyGen(const CBCMasterKey *msk, const CBCPublicIndex *index) 
{
    return NULL;
}

CBCEncryptedPayload *
beEncrypt(const CBCParameters *params, const CBCInput *input)
{
    return NULL;
}

CBCOutput *
beDecrypt(const CBCSecretKey *sk, const CBCEncryptedPayload *payload)
{
    return NULL;
}

CBCEncryptionScheme *CBCEncryptionSchemeBE = &(CBCEncryptionScheme) {
    .Setup = (CBCParameters * (*)(void)) beSetup,
    .CreateMasterKey = (CBCMasterKey * (*)(const CBCParameters *)) beCreateMasterKey,
    .KeyGen = (CBCSecretKey * (*)(const CBCMasterKey *, const CBCPublicIndex *)) beKeyGen,
    .Encrypt = (CBCEncryptedPayload * (*)(const CBCParameters *, const CBCInput *)) beEncrypt,
    .Decrypt = (CBCOutput * (*)(const CBCSecretKey *, const CBCEncryptedPayload *)) beDecrypt,
};
