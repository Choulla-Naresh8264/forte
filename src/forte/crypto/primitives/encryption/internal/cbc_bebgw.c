#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <pbc.h>

#include <forte/crypto/primitives/encryption/cbc_encrypter.h>
#include <forte/crypto/primitives/encryption/internal/cbc_bebgw.h>
#include <forte/string/forte_string.h>

// BE containers
struct cbc_parameters_bebgw {
    element_t g;
    element_t h;
    element_t *gs;
    element_t *hs;
    int groupSize;
    pairing_t pairing;
};
struct cbc_master_key_bebgw {
    element_t publicKey;
    element_t privateKey;
};

struct cbc_secret_key_bebgw {
    element_t g_i_gamma;
    element_t g_i;
    element_t h_i;
    size_t index;
};
struct cbc_public_index_bebgw {
    size_t index;
};
struct cbc_ciphertext_bebgw {
    // Header elements (used to derive encryption/decryption key)
    element_t C0;
    element_t C1;
    int *memberSet;
    size_t numMembers;

    // The actual encrypted data
    ForteString *payload;
    ForteString *iv;
};

struct cbc_encryption_scheme_bebgw {
    BEBGWParameters *params;
    BEBGWMasterKey *msk;
};

BEBGWParameters *
bebgwSetup(size_t groupSize, char *pairFileName)
{
    BEBGWParameters *params = (BEBGWParameters *) malloc(sizeof(BEBGWParameters));

    // Setup curve
    FILE *curveFile = fopen(pairFileName, "rb");
    if(!curveFile) {
        printf("%s doesn't exist! exiting! \n\n", pairFileName);
        return NULL;
    }

    // TODO: get rid of the mofo magic numbers
    char s[8192];
    size_t count = fread(s, 1, 8192, curveFile);
    if (!count) {
        return NULL;
    }
    if (pairing_init_set_buf(params->pairing, s, count)) {
        printf("pairing init failed\n");
        return NULL;
    }
    fclose(curveFile);

    if (groupSize % 8 != 0) {
        printf("\nSystem size must be a multiple of 8\n");
        printf("Didn't finish system setup\n\n");
        return NULL;
    }

    params->groupSize = groupSize;
    element_t *lgs;
    element_t *lhs;
    int i;

    lgs = pbc_malloc(2 * groupSize * sizeof(element_t));
    lhs = pbc_malloc(2 * groupSize * sizeof(element_t));
    if (!(lhs) || !(lgs)) {
        printf("\nMalloc Failed\n");
        printf("Didn't finish system setup\n\n");
    }

    // Choosing random G & H
    element_init(params->g, params->pairing->G1);
    element_random(params->g);
    element_init(params->h, params->pairing->G2);
    element_random(params->h);

    // Pick a random exponent alpha
    element_t alpha;
    element_init_Zr(alpha, params->pairing);
    element_random(alpha);

    // Make the 0th elements equal to x^alpha
    element_init(lgs[0], params->pairing->G1);
    element_init(lhs[0], params->pairing->G2);
    element_pow_zn(lgs[0], params->g, alpha);
    element_pow_zn(lhs[0], params->h, alpha);

    // Fill in the gs and the hs arrays
    for(i = 1; i < 2 * groupSize; i++) {
        element_init(lgs[i], params->pairing->G1);
        element_pow_zn(lgs[i],lgs[i-1], alpha);
        element_init(lhs[i], params->pairing->G2);
        element_pow_zn(lhs[i], lhs[i-1], alpha);
        if (i == groupSize + 1) {
            element_clear(lgs[i-1]);
            element_clear(lhs[i-1]);
        }
    }

    // For simplicity & so code was easy to read
    params->gs = lgs;
    params->hs = lhs;

    element_clear(alpha);

    return params;
}

BEBGWMasterKey *
bebgwCreateMasterKey(BEBGWParameters *params)
{
    BEBGWMasterKey *msk = (BEBGWMasterKey *) malloc(sizeof(BEBGWMasterKey));

    element_init_Zr(msk->privateKey, params->pairing);
    element_random(msk->privateKey);

    element_init(msk->publicKey, params->pairing->G1);
    element_pow_zn(msk->publicKey, params->g, msk->privateKey);

    return msk;
}

BEBGWParameters *
bebgwGetParameters(BEBGWEncryptionScheme *scheme)
{
    return scheme->params;
}

BEBGWMasterKey *
bebgwGetMasterKey(BEBGWEncryptionScheme *scheme)
{
    return scheme->msk;
}

BEBGWSecretKey *
bebgwKeyGen(BEBGWEncryptionScheme *scheme, int index)
{
    BEBGWParameters *params = scheme->params;
    BEBGWMasterKey *msk = scheme->msk;

    BEBGWSecretKey *secretKey = (BEBGWSecretKey *) malloc(sizeof(BEBGWSecretKey));

    element_init(secretKey->g_i_gamma, params->pairing->G1);
    element_init(secretKey->g_i, params->pairing->G1);
    element_init(secretKey->h_i, params->pairing->G2);
    element_set(secretKey->g_i, params->gs[index - 1]);
    element_set(secretKey->h_i, params->hs[index - 1]);
    secretKey->index = index;

    element_pow_zn(secretKey->g_i_gamma, params->gs[index - 1], msk->privateKey);

    return secretKey;
}

BEBGWCiphertext *
bebgwEncrypt(BEBGWEncryptionScheme *scheme, BEBGWParameters *params, int *recipientSet, size_t setLength, ForteString *input)
{
    element_t encryptionProduct;
    element_init(encryptionProduct, params->pairing->G1);
    int n = params->groupSize;

    int firstMember = recipientSet[0];
    if (firstMember < 1 || firstMember > n) {
        printf("element was outside the range of valid users\n");
        printf("only give me valid values.  i die.\n");
        return NULL;
    }

    element_set(encryptionProduct, params->gs[n - firstMember]);
    for (int i = 1; i < setLength; i++) {
        int memberId = recipientSet[i];
        if (memberId < 1 || memberId > n) {
            printf("element %d was outside the range of valid users\n",i);
            printf("only give me valid values.  i die.\n");
            return NULL;
        }
        element_mul(encryptionProduct, encryptionProduct, params->gs[n - memberId]);
    }

    BEBGWCiphertext *ct = (BEBGWCiphertext *) malloc(sizeof(BEBGWCiphertext));

    ct->numMembers = setLength;
    ct->memberSet = (int *) malloc(sizeof(int) * setLength);
    for (int i = 0; i < setLength; i++) {
        ct->memberSet[i] = recipientSet[i];
    }

    element_t t;
    element_init_Zr(t, params->pairing);
    element_random(t);

    element_t key; // the symmetric encryption key
    element_init(key, params->pairing->GT);
    element_init(ct->C0, params->pairing->G2);
    element_init(ct->C1, params->pairing->G1);

    // Compute K
    element_pairing(key, params->gs[params->groupSize - 1], params->hs[0]);
    element_pow_zn(key, key, t);

    // Compute C0
    element_pow_zn(ct->C0, params->h, t);

    // Compute C1
    element_mul(ct->C1, scheme->msk->publicKey, encryptionProduct);
    element_pow_zn(ct->C1, ct->C1, t);
    element_clear(t);

    element_clear(encryptionProduct);

    // Encrypt the input with the symmetric key derived from the "key" element_t
    size_t byteCount = element_length_in_bytes(key);
    uint8_t *keyBytes = (uint8_t *) malloc(byteCount);
    int result = element_to_bytes(keyBytes, key);
    if (result != byteCount) {
        // TODO: error, free
        return NULL;
    }

    element_clear(key);

    // TODO: it'd be better to hash the 156-byte key to a 128-bit element,
    // rather than just truncate the 28 that's left over...
    uint8_t *symmetricKey = (uint8_t *) malloc(32);
    memset(symmetricKey, 0, 32);
    memcpy(symmetricKey, keyBytes, 32); // we require a 256-bit key

    ct->iv = (ForteString *) malloc(sizeof(ForteString));
    ct->iv->length = 16;
    ct->iv->payload = (uint8_t *) malloc(ct->iv->length);
    result = RAND_bytes(ct->iv->payload, ct->iv->length);
    if (result != 1) {
        // TODO: free
        return NULL;
    }

    // encrypt the input with the symmetric key and IV
    ct->payload = encrypt(input, symmetricKey, ct->iv->payload);

    return ct;
}

ForteString *
bebgwDecrypt(BEBGWParameters *params, BEBGWSecretKey *sk, BEBGWCiphertext *ciphertext)
{
    element_t decryptionProduct;
    element_init(decryptionProduct, params->pairing->G1);

    element_t temp;
    element_t temp2;
    element_t di_de;
    element_t temp3;

    element_init(temp, params->pairing->GT);
    element_init(temp2, params->pairing->GT);
    element_init(di_de, params->pairing->G1);
    element_init(temp3, params->pairing->GT);

    int n = params->groupSize;
    int memberId;
    int already_set = 0;

    for(int i = 0; i < ciphertext->numMembers; i++) {
        memberId = ciphertext->memberSet[i];
        if(memberId < 1 || memberId > n) {
            printf("element %d was outside the range of valid users\n", memberId);
            printf("only give me valid values.  i die.\n");
            return NULL;
        }

        if (memberId == sk->index) {
            continue;
        }

        if (!already_set) {
            element_set(decryptionProduct, params->gs[(n - memberId) + sk->index]);
            already_set = 1;
        } else {
            element_mul(decryptionProduct, decryptionProduct, params->gs[(n - memberId) + sk->index]);
        }
    }

    // Generate the numerator
    element_pairing(temp, ciphertext->C1, sk->h_i);

    // G1 element in denom
    element_mul(di_de, sk->g_i_gamma, decryptionProduct);

    // Generate the denominator
    element_pairing(temp2, di_de, ciphertext->C0);

    // Invert the denominator
    element_invert(temp3, temp2);

    element_t key;
    element_init(key, params->pairing->GT);

    // Multiply the numerator by the inverted denominator
    element_mul(key, temp, temp3);

    // We now have the key to decrypt the ciphertext
    size_t byteCount = element_length_in_bytes(key);
    uint8_t *keyBytes = (uint8_t *) malloc(byteCount);
    int result = element_to_bytes(keyBytes, key);
    if (result != byteCount) {
        // TODO: error, free
        return NULL;
    }
    uint8_t *symmetricKey = (uint8_t *) malloc(32);
    memcpy(symmetricKey, keyBytes, 32);

    // encrypt the input with the symmetric key and IV
    ForteString *plaintext = decrypt(ciphertext->payload, symmetricKey, ciphertext->iv->payload);

    return plaintext;
}

BEBGWEncryptionScheme *
bebgwCreate(size_t groupSize, char *pairFileName)
{
    BEBGWEncryptionScheme *scheme = (BEBGWEncryptionScheme *) malloc(sizeof(BEBGWEncryptionScheme));

    scheme->params = bebgwSetup(groupSize, pairFileName);
    scheme->msk = bebgwCreateMasterKey(scheme->params);

    return scheme;
}

CBCEncryptionSchemeInterface *CBCEncryptionSchemeBEBGW = &(CBCEncryptionSchemeInterface) {
    .GenerateMasterKey = (void * (*)(void *scheme, const void *)) bebgwCreateMasterKey,
    .GeneratePrivateKey = (void * (*)(void *scheme, const void *, const void *)) bebgwKeyGen,
    .Encrypt = (void * (*)(void *scheme, const void *, const void *)) bebgwEncrypt,
    .Decrypt = (void * (*)(void *scheme, const void *, const void *)) bebgwDecrypt,
};
