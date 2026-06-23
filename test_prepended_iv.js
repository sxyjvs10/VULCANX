const CryptoJS = require('crypto-js');
const ciphertextB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const rawBytes = CryptoJS.enc.Base64.parse(ciphertextB64);
console.log("Total bytes:", rawBytes.sigBytes);

if (rawBytes.sigBytes > 16) {
    // Extract first 16 bytes as IV
    const iv = CryptoJS.lib.WordArray.create(rawBytes.words.slice(0, 4));
    
    // Extract rest as ciphertext
    const cipherWords = rawBytes.words.slice(4);
    const cipherText = CryptoJS.lib.WordArray.create(cipherWords, rawBytes.sigBytes - 16);
    
    const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherText });

    const keys = ["7x!A%D*G-KaPdSgV", "7x%D*G-KaPdSgV$@", "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q="];
    
    for (let keyStr of keys) {
        let key = keyStr.length > 20 ? CryptoJS.enc.Base64.parse(keyStr) : CryptoJS.enc.Utf8.parse(keyStr);
        try {
            let dec = CryptoJS.AES.decrypt(cipherParams, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
            let res = dec.toString(CryptoJS.enc.Utf8);
            if (res) console.log(`SUCCESS (Prepended IV) with key ${keyStr}:`, res);
        } catch(e) {}
    }
}
