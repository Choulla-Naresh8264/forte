#ifndef libcbc_encrypter_h
#define libcbc_encrypter_h

struct cbc_encryption_scheme;
typedef struct cbc_encryption_scheme CBCEncryptionScheme;

typedef struct cbc_encryption_scheme_interface {
	void *(*GenerateMasterKey)(void *scheme, const void *parameters);
	void *(*GeneratePrivateKey)(void *scheme, const void *masterKey, const void *index);
	void *(*Encrypt)(void *scheme, const void *params, const void *input, const void *metadata);
	void *(*Decrypt)(void *scheme, const void *secretKey, const void *ciphertext);
} CBCEncryptionSchemeInterface;

struct cbc_parameters;
struct cbc_master_key;
struct cbc_secret_key;
struct cbc_public_index;
struct cbc_ciphertext;

typedef struct cbc_parameters CBCParameters;
typedef struct cbc_master_key CBCMasterKey;
typedef struct cbc_secret_key CBCSecretKey;
typedef struct cbc_public_index CBCPublicIndex;
typedef struct cbc_ciphertext CBCCiphertext;

CBCParameters *cbcParameters_Create(void *instance);
CBCMasterKey *cbcMasterKey_Create(void *instance);
CBCSecretKey *cbcSecretKey_Create(void *instance);
CBCCiphertext *cbcCiphertext_Create(void *instance);
CBCPublicIndex *cbcPublicIndex_Create(void *instance);

CBCEncryptionScheme *cbcEncryptionScheme(void *instance, CBCEncryptionSchemeInterface *interface);
CBCMasterKey *cbcGenerateMasterKey(CBCEncryptionScheme *scheme, const CBCParameters *parameters);
CBCSecretKey *cbcGenerateSecretKey(CBCEncryptionScheme *scheme, const CBCMasterKey *masterKey, const CBCPublicIndex *index);
CBCCiphertext *cbcEncrypt(CBCEncryptionScheme *scheme, const CBCParameters *params, const CBCBlob *plaintext, const void *metadata);
CBCBlob *cbcDecrypt(CBCEncryptionScheme *scheme, const CBCSecretKey *secretKey, const CBCCiphertext *ciphertext);

#endif // libcbc_encrypter_h
