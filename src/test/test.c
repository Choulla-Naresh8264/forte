#include "../cbc.h"

int
main(int argc, char** argv)
{
	// Step 1: use concrete options
	DummyEncryptionScheme *scheme = dummyCreate(1);
	DummyParameters *params = dummySetup(2);
	DummyMasterKey *msk = dummyCreateMasterKey(scheme, params);
	DummyPublicIndex *index = dummyCreatePublicIndex(3);
	DummyInput *input = dummyCreateInput(4);
	DummySecretKey *secretKey = dummyKeyGen(scheme, msk, index);
	DummyEncryptedPayload *paylaod = dummyEncrypt(scheme, params, input);
	DummyOutput *output = dummyDecrypt(scheme, secretKey, paylaod);

	// Step 2: Create generic instance and then use the base operations
	CBCEncryptionScheme *encrScheme = cbcEncryptionScheme(scheme, CBCEncryptionSchemeDummy);
	CBCMasterKey *msk2 = cbcGenerateMasterKey(encrScheme, cbcParameters_Create(params));

    return 0;
}