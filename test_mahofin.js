const CryptoJS = require('crypto-js');

const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const keyHex = "912170bec8952371503030303030303030303030303030303030303030303030";
const ivHex = "bec89523715091217030303030303030";

const key = CryptoJS.enc.Hex.parse(keyHex);
const iv = CryptoJS.enc.Hex.parse(ivHex);

try {
    const dec = CryptoJS.AES.decrypt(ciphertext, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    console.log("Mahofin Decrypt Result:", dec.toString(CryptoJS.enc.Utf8));
} catch(e) {
    console.log("Error:", e);
}
