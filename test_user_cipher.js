const CryptoJS = require('crypto-js');

const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";
const keyString = "7x!A%D*G-KaPdSgV";

// Parse key and IV
const key = CryptoJS.enc.Utf8.parse(keyString);
const iv = CryptoJS.enc.Utf8.parse(keyString); 

console.log("Attempting decryption...");

try {
    const dec1 = CryptoJS.AES.decrypt(ciphertext, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    const result1 = dec1.toString(CryptoJS.enc.Utf8);
    if (result1) console.log("CBC Result:", result1);
} catch (e) {}

try {
    const dec2 = CryptoJS.AES.decrypt(ciphertext, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    const result2 = dec2.toString(CryptoJS.enc.Utf8);
    if (result2) console.log("ECB Result:", result2);
} catch (e) {}
