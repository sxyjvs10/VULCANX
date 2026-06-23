const fs = require('fs');

function rotDecrypt(str) {
    let res = "";
    for (let i = 0; i < str.length; i++) {
        res += String.fromCharCode(str.charCodeAt(i) - 1);
    }
    return res;
}

const base64 = "Li4uLi5DRkhKTyFTVEIhUVNKV0JVRiFMRlouLi4uLgtOSkpEWGhKQ0JCTENoSEZVZVZsWDJ4Ujp1UlVFdXljV3ViU2dCSmRQUWRaYjJESnM1TmdmW3pDSHJxcVRwbjBTM0g6R0trN1kxRm9PWTR1cnVXR2ROe2hJdHFuSEs3TlFsZUliRHBCTgshIWJPdm1STGJjNGdiU3FrMFtNeTF6M0gzbFpLRVRJbzpyW3tXe0NsTXhOOFl2YmxjcXAwdjNvRXRRaVtze0ZkbE4LISF6elVLTHh0VU5lZXlrSjkyQmhOQ0JCRj4LISEuLi4uLkZPRSFRVkNNSkQhTEZaLi4uLi4=";
const decoded = Buffer.from(base64, 'base64').toString('utf8');
const decrypted = rotDecrypt(decoded);

// Clean up formatting - handle both standard and potential double-bang variants
const cleanKey = decrypted.replace(/-----BEGIN RSA PRIVATE KEY-----/, "")
                          .replace(/-----END RSA PRIVATE KEY-----/, "")
                          .replace(/-----BEGIN RSA PRIVATE KEY-----/, "")
                          .replace(/-----END PUBLIC KEY-----/, "") // Based on v4 attempt
                          .replace(/[^A-Za-z0-9+/=]/g, "");

const formattedKey = "-----BEGIN RSA PRIVATE KEY-----\n" + 
                     cleanKey.match(/.{1,64}/g).join("\n") + 
                     "\n-----END RSA PRIVATE KEY-----\n";

console.log(formattedKey);
