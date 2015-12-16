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

struct cbc_encryption_scheme_dummy {
    int x;
    DummyParameters *params;
    DummyMasterKey *msk;
};

CBCEncryptionSchemeInterface *CBCEncryptionSchemeDummy = &(CBCEncryptionSchemeInterface) {
    .GenerateMasterKey = (void * (*)(void *scheme, const void *)) dummyCreateMasterKey,
    .GeneratePrivateKey = (void * (*)(void *scheme, const void *, const void *)) dummyKeyGen,
    .Encrypt = (void * (*)(void *scheme, const void *, const void *)) dummyEncrypt,
    .Decrypt = (void * (*)(void *scheme, const void *, const void *)) dummyDecrypt,
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

DummySecretKey *
dummyKeyGen(DummyEncryptionScheme *scheme, const DummyMasterKey *msk, const DummyPublicIndex *index)
{
    DummySecretKey *dummy = (DummySecretKey *) malloc(sizeof(DummySecretKey));
    dummy->x = msk->x + index->x;
    return dummy;
}

DummyCiphertext *
dummyEncrypt(DummyEncryptionScheme *scheme, const DummyParameters *params, const CBCString *input)
{
    DummyCiphertext *enc = (DummyCiphertext *) malloc(sizeof(DummyCiphertext));
    enc->x = input->length;
    return enc;
}

CBCString *
dummyDecrypt(DummyEncryptionScheme *scheme, const DummySecretKey *sk, const DummyCiphertext *payload)
{
    CBCString *dout = (CBCString *) malloc(sizeof(CBCString));
    dout->length = sk->x + payload->x;
    return dout;
}
