#include "../cbc.h"

int
main(int argc, char** argv)
{
	DummyEncryptionScheme *scheme = dummyCreate(1);
	DummyParameters *params = dummySetup(2);

	// Create a generic type using the concrete instances and the right interface

	// CBCMasterKey *msk = cbcGenerateMasterKey(scheme, params);

    return 0;
}
