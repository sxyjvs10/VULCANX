const CryptoJS = require('crypto-js');
const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const keys = ["7x!A%D*G-KaPdSgV", "7x%D*G-KaPdSgV$@"];

for (let keyString of keys) {
    const key = CryptoJS.enc.Utf8.parse(keyString);
    const iv = CryptoJS.enc.Utf8.parse(keyString.substring(0, 16));

    try {
        const dec1 = CryptoJS.AES.decrypt(ciphertext, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        console.log(`CBC Hex (key=${keyString}):`, dec1.toString(CryptoJS.enc.Hex));
    } catch (e) {}

    try {
        const dec2 = CryptoJS.AES.decrypt(ciphertext, key, {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        });
        console.log(`ECB Hex (key=${keyString}):`, dec2.toString(CryptoJS.enc.Hex));
    } catch (e) {}
}
