function rotDecrypt(str) {
    return str.split('').map(c => {
        let code = c.charCodeAt(0);
        if (code === 32) return ' '; // space
        if (code === 33) return '-'; // ! -> -
        if (code >= 34 && code <= 126) {
            return String.fromCharCode(code - 1);
        }
        return c;
    }).join('');
}

const base64 = "Li4uLi5DRkhKTyFTVEIhUVNKV0JVRiFMRlouLi4uLgtOSkpEWGhKQ0JCTENoSEZVZVZsWDJ4Ujp1UlVFdXljV3ViU2dCSmRQUWRaYjJESnM1TmdmW3pDSHJxcVRwbjBTM0g6R0trN1kxRm9PWTR1cnVXR2ROe2hJdHFuSEs3TlFsZUliRHBCTgshIWJPdm1STGJjNGdiU3FrMFtNeTF6M0gzbFpLRVRJbzpyW3tXe0NsTXhOOFl2YmxjcXAwdjNvRXRRaVtze0ZkbE4LISF6elVLTHh0VU5lZXlrSjkyQmhOQ0JCRj4LISEuLi4uLkZPRSFRVkNNSkQhTEZaLi4uLi4=";
const decoded = Buffer.from(base64, 'base64').toString('utf8');
console.log("Decoded Base64:", decoded);
console.log("Rot Decrypted:", rotDecrypt(decoded));
