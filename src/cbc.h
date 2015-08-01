
#ifndef libcbc_h_
#define libcbc_h_

struct cbc_encryption_scheme;
typedef struct cbc_encryption_scheme CBCEncryptionScheme;

struct cbc_encryption_scheme_dummy;
typedef struct cbc_encryption_scheme_dummy DummyEncryptionScheme;

// General
struct cbc_parameters;
struct cbc_master_key;
struct cbc_secret_key;
struct cbc_public_index;
struct cbc_encrypted_payload;
struct cbc_input;
struct cbc_output;

typedef struct cbc_parameters CBCParameters;
typedef struct cbc_master_key CBCMasterKey;
typedef struct cbc_secret_key CBCSecretKey;
typedef struct cbc_public_index CBCPublicIndex;
typedef struct cbc_encrypted_payload CBCEncryptedPayload;
typedef struct cbc_input CBCInput;
typedef struct cbc_output CBCOutput;

// Dummy-specific versions
struct cbc_parameters_dummy;
typedef struct cbc_parameters_dummy DummyParameters;
struct cbc_master_key_dummy;
typedef struct cbc_master_key_dummy DummyMasterKey;
struct cbc_secret_key_dummy;
typedef struct cbc_secret_key_dummy DummySecretKey;
struct cbc_public_index_dummy;
typedef struct cbc_public_index_dummy DummyPublicIndex;
struct cbc_encrypted_payload_dummy;
typedef struct cbc_encrypted_payload_dummy DummyEncryptedPayload;
struct cbc_input_dummy;
typedef struct cbc_input_dummy DummyInput;
struct cbc_output_dummy;
typedef struct cbc_output_dummy DummyOutput;

// typedef enum {
// 	CBCScheme_BE,
// 	CBCScheme_IBE,
// 	CBCScheme_CPABE,
// 	CBCScheme_KPABE,
// 	CBCScheme_RSA,
// 	CBCScheme_Dummy,
// 	CBCScheme_Invalid
// } CBCSchemeType;

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

// generic functions
CBCMasterKey *cbcGenerateMasterKey(CBCEncryptionScheme *scheme, const CBCParameters *parameters);
CBCSecretKey *cbcGenerateSecretKey(CBCEncryptionScheme *scheme, const CBCMasterKey *masterKey, const CBCPublicIndex *index);
CBCEncryptedPayload *cbcEncrypt(CBCEncryptionScheme *scheme, const CBCParameters *params, const CBCInput *input);
CBCOutput *cbcDecrypt(CBCEncryptionScheme *scheme, const CBCSecretKey *secretKey, const CBCEncryptedPayload *encryptedPayload);

// implementation functions
DummyEncryptionScheme *dummyCreate(int x);
DummyParameters *dummySetup(int initial);
DummyMasterKey *dummyCreateMasterKey(DummyEncryptionScheme *scheme, const DummyParameters *parameters);
DummyPublicIndex *dummyCreatePublicIndex(int val);
DummyInput *dummyCreateInput(int val);
DummySecretKey *dummyKeyGen(DummyEncryptionScheme *scheme, const DummyMasterKey *msk, const DummyPublicIndex *index);
DummyEncryptedPayload *dummyEncrypt(DummyEncryptionScheme *scheme, const DummyParameters *params, const DummyInput *input);
DummyOutput *dummyDecrypt(DummyEncryptionScheme *scheme, const DummySecretKey *sk, const DummyEncryptedPayload *payload);

extern CBCEncryptionSchemeInterface *CBCEncryptionSchemeDummy;

#endif /* libcbc_h_ */
