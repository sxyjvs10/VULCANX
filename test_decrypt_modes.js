const CryptoJS = require('crypto-js');
const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";
const keyString = "7x!A%D*G-KaPdSgV";

// 1. Raw key, ECB, PKCS7
try {
    let key = CryptoJS.enc.Utf8.parse(keyString);
    let dec = CryptoJS.AES.decrypt(ciphertext, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
    console.log("ECB PKCS7 Raw:", dec.toString(CryptoJS.enc.Utf8));
} catch(e) {}

// 2. Raw key, CBC, PKCS7, IV=key (first 16 chars)
try {
    let key = CryptoJS.enc.Utf8.parse(keyString);
    let iv = CryptoJS.enc.Utf8.parse(keyString.substring(0, 16));
    let dec = CryptoJS.AES.decrypt(ciphertext, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    console.log("CBC PKCS7 Raw IV=key:", dec.toString(CryptoJS.enc.Utf8));
} catch(e) {}

// 3. Raw key, CBC, PKCS7, IV=empty (all zeros)
try {
    let key = CryptoJS.enc.Utf8.parse(keyString);
    let iv = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");
    let dec = CryptoJS.AES.decrypt(ciphertext, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
    console.log("CBC PKCS7 Raw IV=0:", dec.toString(CryptoJS.enc.Utf8));
} catch(e) {}

// 4. Passphrase
try {
    let dec = CryptoJS.AES.decrypt(ciphertext, keyString);
    console.log("Passphrase:", dec.toString(CryptoJS.enc.Utf8));
} catch(e) {}
