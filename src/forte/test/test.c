#include "../cbc.h"

// void
// testDummy()
// {
// 	DummyEncryptionScheme *scheme = dummyCreate(1);
// 	DummyParameters *params = dummySetup(2);
// 	DummyMasterKey *msk = dummyCreateMasterKey(scheme, params);
// 	DummyPublicIndex *index = dummyCreatePublicIndex(3);
// 	DummyInput *input = dummyCreateInput(4);
// 	DummySecretKey *secretKey = dummyKeyGen(scheme, msk, index);
// 	DummyEncryptedPayload *payload = dummyEncrypt(scheme, params, input);
// 	DummyOutput *output = dummyDecrypt(scheme, secretKey, payload);
// }

void
testRSA(char *public, char *private)
{
	RSAEncryptionScheme *scheme = rsaCreate(public, private);

	// RSAPublicIndex *publicIndex = rsaCreatePublicIndex(scheme);
	RSAMasterKey *msk = rsaGetMasterKey(scheme);
	RSASecretKey *secretKey = rsaKeyGen(scheme);
	RSAParameters *params = rsaGetParameters(scheme);

	uint8_t *payload = (uint8_t *) malloc(1024 / 8);
	memset(payload, 0, 1024 / 8);
	size_t length = 128;
	payload[0] = 0xFF;
	payload[1] = 0xFF;

	CBCBlob *input = createBlob(length, payload);
	RSACiphertext *ciphertext = rsaEncrypt(scheme, params, input);
	rsaDisplay(ciphertext);
	CBCBlob *output = rsaDecrypt(scheme, secretKey, ciphertext);

	free(payload);
	blobDisplay(output);
}

void
testBEBGW(char *pairFileName, int groupSize)
{
	BEBGWEncryptionScheme *scheme = bebgwCreate(groupSize, pairFileName);

	BEBGWMasterKey *msk = bebgwGetMasterKey(scheme);
	BEBGWSecretKey *secretKey = bebgwKeyGen(scheme, 1);
	BEBGWParameters *params = bebgwGetParameters(scheme);

	uint8_t *payload = (uint8_t *) malloc(1024 / 8);
	memset(payload, 0, 1024 / 8);
	size_t length = 128;
	payload[0] = 0xFF;
	payload[1] = 0xFF;

	CBCBlob *input = createBlob(length, payload);
	blobDisplay(input);

	int members[4] = {1,2,3,4};
	BEBGWCiphertext *ciphertext = bebgwEncrypt(scheme, params, members, 4, input);

	CBCBlob *output = bebgwDecrypt(params, secretKey, ciphertext);

	blobDisplay(output);
}

int
main(int argc, char** argv)
{
	// testDummy();
	testRSA("./data/public.pem", "./data/private.pem");
	testBEBGW("./data/d201.param", 64);

	return 0;
}
