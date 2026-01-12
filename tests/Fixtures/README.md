Helping with JWT
================

## RSA Keys (RS256, RS384, RS512)

```sh
# Generate private key
openssl genrsa -out test-private-key.pem 2048

# Extract public key
openssl rsa -in test-private-key.pem -pubout -out test-public-key.pem
```

## ECDSA Keys (ES256, ES384, ES512)

### ES256 (P-256 curve)
```sh
# Generate private key
openssl ecparam -name prime256v1 -genkey -noout -out test-es256-private-key.pem

# Extract public key
openssl ec -in test-es256-private-key.pem -pubout -out test-es256-public-key.pem

# Convert to PKCS#8 format for jwt.io
openssl pkcs8 -topk8 -nocrypt -in test-es256-private-key.pem -out test-es256-private-key-pkcs8.pem
```

### ES384 (P-384 curve)
```sh
# Generate private key
openssl ecparam -name secp384r1 -genkey -noout -out test-es384-private-key.pem

# Extract public key
openssl ec -in test-es384-private-key.pem -pubout -out test-es384-public-key.pem
```

### ES512 (P-521 curve)
```sh
# Generate private key
openssl ecparam -name secp521r1 -genkey -noout -out test-es512-private-key.pem

# Extract public key
openssl ec -in test-es512-private-key.pem -pubout -out test-es512-public-key.pem
```

## Using with jwt.io

### For ES256
1. Go to https://jwt.io/
2. Select algorithm: ES256
3. For verification (checking existing JWT):
   - Paste the content of `test-es256-public-key.pem` into the **public key** field
   - Paste your JWT token into the encoded field
   - If the signature is valid, you'll see "Signature Verified"
4. For signing (creating JWT):
   - Paste the content of `test-es256-private-key-pkcs8.pem` into the **private key** field (must be PKCS#8 format)

**Key format notes:**
- Public keys: Standard PEM format (`BEGIN PUBLIC KEY`) works directly
- Private keys for signing: Must be PKCS#8 format (`BEGIN PRIVATE KEY`), not SEC1 format (`BEGIN EC PRIVATE KEY`)
- To view key content: `cat test-es256-public-key.pem`
