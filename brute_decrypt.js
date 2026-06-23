const CryptoJS = require('crypto-js');
const fs = require('fs');

const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const keys = [
  "7x%D*G-KaPdSgV$@", // k
  "7x!A%D*G-KaPdSgV", // k1
  "@#$%^&*", // sp
  "TMP190729142821542PK5XHYR1T4L43W",
  "TMP190729191429620D4C271BEE9ZCG9",
  "TMP190731163234904MFLJU9C2GCUMK3",
];

console.log("Starting brute force...");

for (let keyStr of keys) {
    let keyUtf8 = CryptoJS.enc.Utf8.parse(keyStr);
    
    // Test ECB
    try {
        let dec = CryptoJS.AES.decrypt(ciphertext, keyUtf8, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
        let res = dec.toString(CryptoJS.enc.Utf8);
        if (res) console.log(`SUCCESS (ECB, key=${keyStr}):`, res);
    } catch(e) {}
    
    // Test CBC with iv = key
    try {
        let dec = CryptoJS.AES.decrypt(ciphertext, keyUtf8, { iv: keyUtf8, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
        let res = dec.toString(CryptoJS.enc.Utf8);
        if (res) console.log(`SUCCESS (CBC iv=key, key=${keyStr}):`, res);
    } catch(e) {}
    
    // Test CBC with iv = 0
    try {
        let iv = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");
        let dec = CryptoJS.AES.decrypt(ciphertext, keyUtf8, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
        let res = dec.toString(CryptoJS.enc.Utf8);
        if (res) console.log(`SUCCESS (CBC iv=0, key=${keyStr}):`, res);
    } catch(e) {}

    // Test password based (EvpKDF)
    try {
        let dec = CryptoJS.AES.decrypt(ciphertext, keyStr);
        let res = dec.toString(CryptoJS.enc.Utf8);
        if (res) console.log(`SUCCESS (Passphrase, key=${keyStr}):`, res);
    } catch(e) {}
}
console.log("Finished brute force.");
