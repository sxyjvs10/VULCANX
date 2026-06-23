const CryptoJS = require('crypto-js');

const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const key = "auditappkey";

try {
    let dec = CryptoJS.AES.decrypt(ciphertext, key);
    console.log("Decrypted with passphrase:", dec.toString(CryptoJS.enc.Utf8));
} catch(e) {}
