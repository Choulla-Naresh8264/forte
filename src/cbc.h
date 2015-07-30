
#ifndef libcbc_h_
#define libcbc_h_

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

struct cbc_parameters_be;
typedef struct cbc_parameters_be CBCParametersBE;

typedef enum {
	CBCScheme_BE,
	CBCScheme_IBE,
	CBCScheme_CPABE,
	CBCScheme_KPABE,
	CBCScheme_RSA,
} CBCSchemeType;

typedef struct cbc_encryption_scheme {
	CBCParameters *(*Setup)(void);
	CBCMasterKey *(*CreateMasterKey)(const CBCParameters *parameters);
	CBCSecretKey *(*KeyGen)(const CBCMasterKey *masterKey, const CBCPublicIndex *index);
	CBCEncryptedPayload *(*Encrypt)(const CBCParameters *params, const CBCInput *input);
	CBCOutput *(*Decrypt)(const CBCSecretKey *secretKey, const CBCEncryptedPayload *encryptedPayload);
} CBCEncryptionScheme;

typedef struct cbc_signature_scheme {
	CBCParameters *(*Setup)(void);
	CBCMasterKey *(*CreateMasterKey)(const CBCParameters *parameters);
	CBCSecretKey *(*KeyGen)(const CBCMasterKey *masterKey, const CBCPublicIndex *index);
	CBCEncryptedPayload *(*Sign)(const CBCParameters *params, const CBCInput *input);
	CBCOutput *(*Verify)(const CBCSecretKey *secretKey, const CBCEncryptedPayload *encryptedPayload);
} CBCSignatureScheme;

extern CBCEncryptionScheme *CBCEncryptionSchemeBE;

#endif /* libcbc_h_ */
