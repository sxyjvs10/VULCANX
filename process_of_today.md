# Investigation Progress - Cryptography & Keys

## Discoveries Today
1. **AES Key Extraction & Verification**:
   - The hardcoded/obfuscated AES key was successfully extracted as `"7x!A%D*G-KaPdSgV"` (Hex: `3778214125442a472d4b615064536756`).
   - We verified this key is used for encrypting requests (e.g., `request.txt`).
   - Decryption of `request.txt` using `AES-128-CBC` with this key and IV (both set to `"7x!A%D*G-KaPdSgV"`) revealed the plaintext JSON: `{"USERID":"152775","loanID":"789632145"}`.

2. **RSA Key Analysis**:
   - Found several base64-encoded encrypted RSA keys in the Javascript chunks (e.g., `privateClientEn`, `bigPriEn`, `privateClientBaseEn`, `bigPriBaseEn` inside `chunk-LEM5WUQO.js`).
   - Mapped `Target 2` Modulus to `chunk-CFULGL53.js`.
   - `target_pub.pem` has parsing issues in OpenSSL/Python, but its modulus doesn't seem to perfectly match the initially extracted private keys.
   - We attempted to decrypt `privateClientEn` and `bigPriEn` with the AES key, but our initial tests failed (possibly different padding, mode, or a different AES key is used to protect the RSA keys).

## Next Steps
- Determine the correct decryption algorithm and parameters for `privateClientEn` and `bigPriEn`.
- Investigate `target_pub.pem` parsing issues to find its matching private key.
- Review where `privateClientEn` is passed into the WebCrypto API or CryptoJS to understand how the application decrypts its own RSA private keys.
