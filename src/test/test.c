#include "../cbc.h"

int
main(int argc, char** argv)
{
	DummyEncryptionScheme *scheme = dummyCreate(1);
	DummyParameters *params = dummySetup(2);

	// CBCMasterKey *msk = cbcGenerateMasterKey(scheme, params);

    return 0;
}