#ifndef libforte_encrypter_h
#define libforte_encrypter_h

#include <forte/string/forte_string.h>

struct forte_encryption_scheme;
typedef struct forte_encryption_scheme ForteEncryptionScheme;

typedef struct forteEncryption_encryption_scheme_interface {
	void *(*GenerateMasterKey)(void *scheme, const void *parameters);
	void *(*GeneratePrivateKey)(void *scheme, const void *masterKey, const void *index);
	void *(*Encrypt)(void *scheme, const void *params, const void *input, const void *metadata);
	void *(*Decrypt)(void *scheme, const void *secretKey, const void *ciphertext);
} ForteEncryptorInterface;

struct forte_parameters;
struct forte_master_key;
struct forte_secret_key;
struct forte_public_index;
struct forte_ciphertext;

typedef struct forte_parameters ForteEncryptionParameters;
typedef struct forte_master_key ForteEncryptionMasterKey;
typedef struct forte_secret_key ForteEncryptionSecretKey;
typedef struct forte_public_index ForteEncryptionPublicIndex;
typedef struct forte_ciphertext ForteEncryptionCiphertext;

// TODO: rename these functions
ForteString *encrypt(ForteString *input, ForteString *key, ForteString *iv);
ForteString *decrypt(ForteString *ciphertext, ForteString *key, ForteString *iv);

ForteEncryptionParameters *forteEncryptionParameters_Create(void *instance);
ForteEncryptionMasterKey *forteEncryptionMasterKey_Create(void *instance);
ForteEncryptionSecretKey *forteEncryptionSecretKey_Create(void *instance);
ForteEncryptionCiphertext *forteEncryptionCiphertext_Create(void *instance);
ForteEncryptionPublicIndex *forteEncryptionPublicIndex_Create(void *instance);

ForteEncryptionScheme *forteEncryptionScheme(void *instance, ForteEncryptorInterface *interface);
ForteEncryptionMasterKey *forteEncryptionGenerateMasterKey(ForteEncryptionScheme *scheme, const ForteEncryptionParameters *parameters);
ForteEncryptionSecretKey *forteEncryptionGenerateSecretKey(ForteEncryptionScheme *scheme, const ForteEncryptionMasterKey *masterKey, const ForteEncryptionPublicIndex *index);
ForteEncryptionCiphertext *forteEncryptionEncrypt(ForteEncryptionScheme *scheme, const ForteEncryptionParameters *params, const ForteString *plaintext, const void *metadata);
ForteString *forteEncryptionDecrypt(ForteEncryptionScheme *scheme, const ForteEncryptionSecretKey *secretKey, const ForteEncryptionCiphertext *ciphertext);

#endif // libforte_encrypter_h
