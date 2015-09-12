#ifndef libcbc_h_
#define libcbc_h_

#include <stdint.h>
#include <stddef.h>

struct cbc_encryption_scheme;
typedef struct cbc_encryption_scheme CBCEncryptionScheme;

struct cbc_encryption_scheme_dummy;
typedef struct cbc_encryption_scheme_dummy DummyEncryptionScheme;

struct cbc_encryption_scheme_rsa;
typedef struct cbc_encryption_scheme_rsa RSAEncryptionScheme;

struct cbc_encryption_scheme_bebgw;
typedef struct cbc_encryption_scheme_bebgw BEBGWEncryptionScheme;


// General
struct cbc_parameters;
struct cbc_master_key;
struct cbc_secret_key;
struct cbc_public_index;
struct cbc_ciphertext;
struct cbc_blob;

typedef struct cbc_parameters CBCParameters; // msk and params
typedef struct cbc_master_key CBCMasterKey; // both public and private
typedef struct cbc_secret_key CBCSecretKey; // secret RSA key
typedef struct cbc_public_index CBCPublicIndex; // public RSA key
typedef struct cbc_ciphertext CBCCiphertext;
typedef struct cbc_blob CBCBlob;

// Dummy-specific versions
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

// RSA versions
struct cbc_parameters_rsa;
typedef struct cbc_parameters_rsa RSAParameters;
struct cbc_master_key_rsa;
typedef struct cbc_master_key_rsa RSAMasterKey;
struct cbc_secret_key_rsa;
typedef struct cbc_secret_key_rsa RSASecretKey;
struct cbc_public_index_rsa;
typedef struct cbc_public_index_rsa RSAPublicIndex;
struct cbc_ciphertext_rsa;
typedef struct cbc_ciphertext_rsa RSACiphertext;

// BEBGW versions
struct cbc_parameters_bebgw;
typedef struct cbc_parameters_bebgw BEBGWParameters;
struct cbc_master_key_bebgw;
typedef struct cbc_master_key_bebgw BEBGWMasterKey;
struct cbc_secret_key_bebgw;
typedef struct cbc_secret_key_bebgw BEBGWSecretKey;
struct cbc_public_index_bebgw;
typedef struct cbc_public_index_bebgw BEBGWPublicIndex;
struct cbc_ciphertext_bebgw;
typedef struct cbc_ciphertext_bebgw BEBGWCiphertext;

typedef enum {
	CBCScheme_RSA,
	CBCScheme_BE,
	CBCScheme_Dummy,
	CBCScheme_Invalid
} CBCSchemeType;

struct cbc_encoded_value;
typedef struct cbc_encoded_value CBCEncodedValue;

typedef struct cbc_encoder_interface {
	CBCEncodedValue *(*Encode)(void *instance);
	void *(*Decode)(CBCEncodedValue *encodedValue);
} CBCEncoder;

typedef struct cbc_encryption_scheme_interface {
	void *(*GenerateMasterKey)(void *scheme, const void *parameters);
	void *(*GeneratePrivateKey)(void *scheme, const void *masterKey, const void *index);
	void *(*Encrypt)(void *scheme, const void *params, const void *input);
	void *(*Decrypt)(void *scheme, const void *secretKey, const void *encryptedPayload);
} CBCEncryptionSchemeInterface;

typedef struct cbc_signature_scheme_interface {
	void *(*GenerateMasterKey)(void *scheme, const void *parameters);
	void *(*GeneratePrivateKey)(void *scheme, const void *masterKey, const void *index);
	void *(*Sign)(void *scheme, const CBCParameters *params, const void *input);
	void *(*Verify)(void *scheme, const void *secretKey, const void *encryptedPayload);
} CBCSignatureSchemeInterface;

// TODO: these could be macros
CBCParameters *cbcParameters_Create(void *instance);
CBCMasterKey *cbcMasterKey_Create(void *instance);
CBCSecretKey *cbcSecretKey_Create(void *instance);
CBCCiphertext *cbcCiphertext_Create(void *instance);
CBCPublicIndex *cbcPublicIndex_Create(void *instance);

// generic functions
CBCEncryptionScheme *cbcEncryptionScheme(void *instance, CBCEncryptionSchemeInterface *interface);
CBCMasterKey *cbcGenerateMasterKey(CBCEncryptionScheme *scheme, const CBCParameters *parameters);
CBCSecretKey *cbcGenerateSecretKey(CBCEncryptionScheme *scheme, const CBCMasterKey *masterKey, const CBCPublicIndex *index);
CBCCiphertext *cbcEncrypt(CBCEncryptionScheme *scheme, const CBCParameters *params, const CBCBlob *input);
CBCBlob *cbcDecrypt(CBCEncryptionScheme *scheme, const CBCSecretKey *secretKey, const CBCCiphertext *encryptedPayload);

// implementation functions
DummyEncryptionScheme *dummyCreate(int x);
// DummyParameters *dummySetup(int initial);
// DummyMasterKey *dummyCreateMasterKey(DummyEncryptionScheme *scheme, const DummyParameters *parameters);
DummyPublicIndex *dummyCreatePublicIndex(int val);
CBCBlob *dummyCreateInput(int val);
DummySecretKey *dummyKeyGen(DummyEncryptionScheme *scheme, const DummyMasterKey *msk, const DummyPublicIndex *index);
DummyCiphertext *dummyEncrypt(DummyEncryptionScheme *scheme, const DummyParameters *params, const CBCBlob *input);
CBCBlob *dummyDecrypt(DummyEncryptionScheme *scheme, const DummySecretKey *sk, const DummyCiphertext *payload);

CBCBlob *createInput(size_t length, uint8_t input[length]);

// rsa implementation functions
RSAEncryptionScheme *rsaCreate(char *publicKeyPemFile, char *privateKey);
RSAParameters *rsaGetParameters(RSAEncryptionScheme *scheme);
RSAMasterKey *rsaGetMasterKey(RSAEncryptionScheme *scheme);
RSAPublicIndex *rsaCreatePublicIndex(RSAEncryptionScheme *scheme);
RSASecretKey *rsaKeyGen(RSAEncryptionScheme *scheme);
RSACiphertext *rsaEncrypt(RSAEncryptionScheme *scheme, const RSAParameters *params, const CBCBlob *input);
CBCBlob *rsaDecrypt(RSAParameters *params, const RSASecretKey *sk, const RSACiphertext *payload);

// bebgw
BEBGWEncryptionScheme *bebgwCreate(size_t groupSize, char *pairFileName);
BEBGWParameters *bebgwGetParameters(BEBGWEncryptionScheme *scheme);
BEBGWMasterKey *bebgwGetMasterKey(BEBGWEncryptionScheme *scheme);
BEBGWPublicIndex *bebgwCreatePublicIndex(BEBGWEncryptionScheme *scheme);
CBCBlob *bebgwCreateInput(size_t length, uint8_t input[length]);
BEBGWSecretKey *bebgwKeyGen(BEBGWEncryptionScheme *scheme, int index);
BEBGWCiphertext *bebgwEncrypt(BEBGWEncryptionScheme *scheme, BEBGWParameters *params, int *recipientSet, size_t setLength, CBCBlob *input);
CBCBlob *bebgwDecrypt(BEBGWParameters *params, BEBGWSecretKey *sk, BEBGWCiphertext *payload);

void blobDisplay(CBCBlob *output);
void rsaDisplay(RSACiphertext *ct);

extern CBCEncryptionSchemeInterface *CBCEncryptionSchemeDummy;

#endif /* libcbc_h_ */
