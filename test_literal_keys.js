const CryptoJS = require('crypto-js');
const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const keys = [
    "N3ghQSVEKkctS2FQZFNnVg==",
    "N3glRCpHLUthUGRTZ1YkQA==",
    "QCMkJV4mKg"
];

for (let keyString of keys) {
    const key = CryptoJS.enc.Utf8.parse(keyString);
    const iv = CryptoJS.enc.Utf8.parse(keyString);

    try {
        const dec1 = CryptoJS.AES.decrypt(ciphertext, key, {
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        const res1 = dec1.toString(CryptoJS.enc.Utf8);
        if (res1) console.log(`SUCCESS CBC (keyString=${keyString}):`, res1);
    } catch (e) {}

    try {
        const dec2 = CryptoJS.AES.decrypt(ciphertext, key, {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        });
        const res2 = dec2.toString(CryptoJS.enc.Utf8);
        if (res2) console.log(`SUCCESS ECB (keyString=${keyString}):`, res2);
    } catch (e) {}
}
