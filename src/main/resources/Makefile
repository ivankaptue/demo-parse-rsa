.PHONY: privateKey
privateKey:
	openssl genrsa -out private_key.pem 2048

.PHONY: publicKey
publicKey: privateKey
	openssl rsa -pubout -in private_key.pem -out public_key.pem

.PHONY: convertPrivateKey
convertPrivateKey: publicKey
	openssl pkcs8 -topk8 -in private_key.pem -inform pem -out private_key_pkcs8.pem -outform pem -nocrypt

.PHONY: keys
keys: convertPrivateKey
