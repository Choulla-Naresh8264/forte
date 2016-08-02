#ifndef libcbc_authenticator_h_
#define libcbc_authenticator_h_

typedef struct cbc_signature_scheme_interface {
	void *(*GenerateMasterKey)(void *scheme, const void *parameters);
	void *(*GeneratePrivateKey)(void *scheme, const void *masterKey, const void *index);
	void *(*Sign)(void *scheme, const ForteParameters *params, const void *input);
	void *(*Verify)(void *scheme, const void *secretKey, const void *encryptedPayload);
} ForteSignatureSchemeInterface;

#endif // libcbc_authenticator_h_
