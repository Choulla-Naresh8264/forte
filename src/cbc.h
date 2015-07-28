

(CBCParameters, CBCMasterKey) = Setup(parameter)
CBCSecretKey = KeyGen(CBCMasterKey, CBCPublicIndex)
CBCEncryptedPayload = Encrypt(CBCPublicParameters, CBCInput)   
CBCOutput = Decrypt(CBCSecretKey, CBCEncryptedPayload)    
// y is the desired output of the function


CBCIdentity

CBCPublicKey
CBCPrivateKey
CBCMasterKey
CBCParameters
CBCIndex

CBCKeyGenerator

CBCBuffer
CBCSignature

CBCSigner
CBCVerifier
CBCEncryptor
CNCDecryptor

CBCScheme


