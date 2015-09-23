#ifndef libcbc_encrypter_dummy_h_
#define libcbc_encrypter_dummy_h_

struct cbc_encryption_scheme_dummy;
typedef struct cbc_encryption_scheme_dummy DummyEncryptionScheme;

struct cbc_parameters_dummy;
typedef struct cbc_parameters_dummy DummyParameters;
struct cbc_master_key_dummy;
typedef struct cbc_master_key_dummy DummyMasterKey;
struct cbc_secret_key_dummy;
typedef struct cbc_secret_key_dummy DummySecretKey;
struct cbc_public_index_dummy;
typedef struct cbc_public_index_dummy DummyPublicIndex;
struct cbc_ciphertext_dummy;
typedef struct cbc_ciphertext_dummy DummyCiphertext;

DummyEncryptionScheme *dummyCreate(int x);
DummyPublicIndex *dummyCreatePublicIndex(int val);
CBCBlob *dummyCreateInput(int val);
DummySecretKey *dummyKeyGen(DummyEncryptionScheme *scheme, const DummyMasterKey *msk, const DummyPublicIndex *index);
DummyCiphertext *dummyEncrypt(DummyEncryptionScheme *scheme, const DummyParameters *params, const CBCBlob *input);
CBCBlob *dummyDecrypt(DummyEncryptionScheme *scheme, const DummySecretKey *sk, const DummyCiphertext *payload);

#endif // libcbc_encrypter_dummy_h_
