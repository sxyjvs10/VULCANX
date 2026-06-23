const CryptoJS = require('crypto-js');

const ciphertext = "ayR96vd5+QjWop+CwfIK5A==";
const keyString = "7x!A%D*G-KaPdSgV";

// Parse key and IV
const key = CryptoJS.enc.Utf8.parse(keyString);
// From our live exploit logs, the IV hex matched the key hex
const iv = CryptoJS.enc.Utf8.parse(keyString); 

console.log("Attempting decryption...");

// Attempt 1: CBC (Default in CryptoJS)
try {
    const dec1 = CryptoJS.AES.decrypt(ciphertext, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    const result1 = dec1.toString(CryptoJS.enc.Utf8);
    if (result1) console.log("CBC Result:", result1);
} catch (e) {}

// Attempt 2: ECB (No IV used)
try {
    const dec2 = CryptoJS.AES.decrypt(ciphertext, key, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    const result2 = dec2.toString(CryptoJS.enc.Utf8);
    if (result2) console.log("ECB Result:", result2);
} catch (e) {}

// Let's also check if the ciphertext is passed differently (e.g. format)
