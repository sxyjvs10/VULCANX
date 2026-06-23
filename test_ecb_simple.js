const CryptoJS = require('crypto-js');
const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const keys = ["7x!A%D*G-KaPdSgV", "7x%D*G-KaPdSgV$@"];

for (let k of keys) {
    console.log("Testing:", k);
    let key = CryptoJS.enc.Utf8.parse(k);
    try {
        let dec = CryptoJS.AES.decrypt(ciphertext, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
        let hex = dec.toString(CryptoJS.enc.Hex);
        let utf8 = dec.toString(CryptoJS.enc.Utf8);
        console.log("  Hex:", hex);
        console.log("  UTF8:", utf8);
    } catch(e) {
        console.log("  Error:", e.message);
    }
}
