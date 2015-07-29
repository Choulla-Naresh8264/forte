#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "cbc.h"

CBCParameters *
beSetup(void) 
{
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


