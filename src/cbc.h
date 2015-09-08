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
struct cbc_encrypted_payload;
struct cbc_input;
struct cbc_output;

typedef struct cbc_parameters CBCParameters; // msk and params
typedef struct cbc_master_key CBCMasterKey; // both public and private
typedef struct cbc_secret_key CBCSecretKey; // secret RSA key
typedef struct cbc_public_index CBCPublicIndex; // public RSA key
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

// RSA versions
struct cbc_parameters_rsa;
typedef struct cbc_parameters_rsa RSAParameters;
struct cbc_master_key_rsa;
typedef struct cbc_master_key_rsa RSAMasterKey;
struct cbc_secret_key_rsa;
typedef struct cbc_secret_key_rsa RSASecretKey;
struct cbc_public_index_rsa;
typedef struct cbc_public_index_rsa RSAPublicIndex;
struct cbc_encrypted_payload_rsa;
typedef struct cbc_encrypted_payload_rsa RSAEncryptedPayload;
struct cbc_input_rsa;
typedef struct cbc_input_rsa RSAInput;
struct cbc_output_rsa;
typedef struct cbc_output_rsa RSAOutput;

// BEBGW versions
struct cbc_parameters_bebgw;
typedef struct cbc_parameters_bebgw BEBGWParameters;
struct cbc_master_key_bebgw;
typedef struct cbc_master_key_bebgw BEBGWMasterKey;
struct cbc_secret_key_bebgw;
typedef struct cbc_secret_key_bebgw BEBGWSecretKey;
struct cbc_public_index_bebgw;
typedef struct cbc_public_index_bebgw BEBGWPublicIndex;
struct cbc_encrypted_payload_bebgw;
typedef struct cbc_encrypted_payload_bebgw BEBGWEncryptedPayload;
struct cbc_input_bebgw;
typedef struct cbc_input_bebgw BEBGWInput;
struct cbc_output_bebgw;
typedef struct cbc_output_bebgw BEBGWOutput;

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
CBCInput *cbcInput_Create(void *instance);
CBCEncryptedPayload *cbcEncryptedPayload_Create(void *instance);
CBCOutput *cbcOutput_Create(void *instance);
CBCPublicIndex *cbcPublicIndex_Create(void *instance);

// generic functions
CBCEncryptionScheme *cbcEncryptionScheme(void *instance, CBCEncryptionSchemeInterface *interface);
CBCMasterKey *cbcGenerateMasterKey(CBCEncryptionScheme *scheme, const CBCParameters *parameters);
CBCSecretKey *cbcGenerateSecretKey(CBCEncryptionScheme *scheme, const CBCMasterKey *masterKey, const CBCPublicIndex *index);
CBCEncryptedPayload *cbcEncrypt(CBCEncryptionScheme *scheme, const CBCParameters *params, const CBCInput *input);
CBCOutput *cbcDecrypt(CBCEncryptionScheme *scheme, const CBCSecretKey *secretKey, const CBCEncryptedPayload *encryptedPayload);

// implementation functions
DummyEncryptionScheme *dummyCreate(int x);
// DummyParameters *dummySetup(int initial);
// DummyMasterKey *dummyCreateMasterKey(DummyEncryptionScheme *scheme, const DummyParameters *parameters);
DummyPublicIndex *dummyCreatePublicIndex(int val);
DummyInput *dummyCreateInput(int val);
DummySecretKey *dummyKeyGen(DummyEncryptionScheme *scheme, const DummyMasterKey *msk, const DummyPublicIndex *index);
DummyEncryptedPayload *dummyEncrypt(DummyEncryptionScheme *scheme, const DummyParameters *params, const DummyInput *input);
DummyOutput *dummyDecrypt(DummyEncryptionScheme *scheme, const DummySecretKey *sk, const DummyEncryptedPayload *payload);

// rsa implementation functions
RSAEncryptionScheme *rsaCreate(char *publicKeyPemFile, char *privateKey);
RSAParameters *rsaGetParameters(RSAEncryptionScheme *scheme);
RSAMasterKey *rsaGetMasterKey(RSAEncryptionScheme *scheme);
RSAPublicIndex *rsaCreatePublicIndex(RSAEncryptionScheme *scheme);
RSAInput *rsaCreateInput(size_t length, uint8_t input[length]);
RSASecretKey *rsaKeyGen(RSAEncryptionScheme *scheme);
RSAEncryptedPayload *rsaEncrypt(RSAEncryptionScheme *scheme, const RSAParameters *params, const RSAInput *input);
RSAOutput *rsaDecrypt(RSAParameters *params, const RSASecretKey *sk, const RSAEncryptedPayload *payload);

// bebgw
BEBGWEncryptionScheme *bebgwCreate(size_t groupSize, char *pairFileName);
BEBGWParameters *bebgwGetParameters(BEBGWEncryptionScheme *scheme);
BEBGWMasterKey *bebgwGetMasterKey(BEBGWEncryptionScheme *scheme);
BEBGWPublicIndex *bebgwCreatePublicIndex(BEBGWEncryptionScheme *scheme);
BEBGWInput *bebgwCreateInput(size_t length, uint8_t input[length]);
BEBGWSecretKey *bebgwKeyGen(BEBGWEncryptionScheme *scheme, int index);
BEBGWEncryptedPayload *bebgwEncrypt(BEBGWEncryptionScheme *scheme, const BEBGWParameters *params, const BEBGWInput *input);
BEBGWOutput *bebgwDecrypt(BEBGWParameters *params, const BEBGWSecretKey *sk, const BEBGWEncryptedPayload *payload);

void rsaDisplayCiphertext(RSAEncryptedPayload *output);
void rsaDisplay(RSAOutput *output);

extern CBCEncryptionSchemeInterface *CBCEncryptionSchemeDummy;

#endif /* libcbc_h_ */
