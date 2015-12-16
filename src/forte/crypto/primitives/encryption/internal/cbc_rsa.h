#ifndef libcbc_encrypter_rsa_h
#define libcbc_encrypter_rsa_h

#include "forte_string.h"

struct cbc_encryption_scheme_rsa;
typedef struct cbc_encryption_scheme_rsa RSAEncryptionScheme;

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

RSAEncryptionScheme *rsaCreate(char *publicKeyPemFile, char *privateKey);
RSAParameters *rsaGetParameters(RSAEncryptionScheme *scheme);
RSAMasterKey *rsaGetMasterKey(RSAEncryptionScheme *scheme);
RSAPublicIndex *rsaCreatePublicIndex(RSAEncryptionScheme *scheme);
RSASecretKey *rsaKeyGen(RSAEncryptionScheme *scheme);
RSACiphertext *rsaEncrypt(RSAEncryptionScheme *scheme, const RSAParameters *params, const ForteString *input);
ForteString *rsaDecrypt(RSAParameters *params, const RSASecretKey *sk, const RSACiphertext *payload);

#endif // libcbc_encrypter_rsa_h
