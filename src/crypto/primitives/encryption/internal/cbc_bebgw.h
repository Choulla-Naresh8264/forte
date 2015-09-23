#ifndef libcbc_encrypter_bebgw_h
#define libcbc_encrypter_bebgw_h

struct cbc_encryption_scheme_bebgw;
typedef struct cbc_encryption_scheme_bebgw BEBGWEncryptionScheme;

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

BEBGWEncryptionScheme *bebgwCreate(size_t groupSize, char *pairFileName);
BEBGWParameters *bebgwGetParameters(BEBGWEncryptionScheme *scheme);
BEBGWMasterKey *bebgwGetMasterKey(BEBGWEncryptionScheme *scheme);
BEBGWPublicIndex *bebgwCreatePublicIndex(BEBGWEncryptionScheme *scheme);
CBCBlob *bebgwCreateInput(size_t length, uint8_t input[length]);
BEBGWSecretKey *bebgwKeyGen(BEBGWEncryptionScheme *scheme, int index);
BEBGWCiphertext *bebgwEncrypt(BEBGWEncryptionScheme *scheme, BEBGWParameters *params, int *recipientSet, size_t setLength, CBCBlob *input);
CBCBlob *bebgwDecrypt(BEBGWParameters *params, BEBGWSecretKey *sk, BEBGWCiphertext *payload);

#endif // libcbc_encrypter_bebgw_h
