#include "../cbc.h"

int
main(int argc, char** argv)
{
	// Step 1: use concrete options
	// DummyEncryptionScheme *scheme = dummyCreate(1);
	// DummyParameters *params = dummySetup(2);
	// DummyMasterKey *msk = dummyCreateMasterKey(scheme, params);
	// DummyPublicIndex *index = dummyCreatePublicIndex(3);
	// DummyInput *input = dummyCreateInput(4);
	// DummySecretKey *secretKey = dummyKeyGen(scheme, msk, index);
	// DummyEncryptedPayload *payload = dummyEncrypt(scheme, params, input);
	// DummyOutput *output = dummyDecrypt(scheme, secretKey, payload);

	// Create a generic type using the concrete instances and the right interface
	// Step 2: Create generic instance and then use the base operations
	// CBCEncryptionScheme *encrScheme = cbcEncryptionScheme(scheme, CBCEncryptionSchemeDummy);
	// CBCMasterKey *msk2 = cbcGenerateMasterKey(encrScheme, cbcParameters_Create(params));

	RSAEncryptionScheme *scheme = rsaCreate("./data/public.pem", "./data/private.pem");

	// RSAPublicIndex *publicIndex = rsaCreatePublicIndex(scheme);
	RSAMasterKey *msk = rsaGetMasterKey(scheme);
	RSASecretKey *secretKey = rsaKeyGen(scheme);
	RSAParameters *params = rsaGetParameters(scheme);

	// TODO: note that the payload cannot exceed the size of the key...

	uint8_t *payload = (uint8_t *) malloc(1024 / 8);
	memset(payload, 0, 1024 / 8);
	size_t length = 128;
	payload[0] = 0xFF;
	payload[1] = 0xFF;

	CBCBlob *input = rsaCreateInput(length, payload);
	RSACiphertext *ciphertext = rsaEncrypt(scheme, params, input);
	blobDisplay(ciphertext);
	CBCBlob *output = rsaDecrypt(scheme, secretKey, ciphertext);

	free(payload);
	blobDisplay(output);

	return 0;
}
