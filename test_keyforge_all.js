const crypto = require('crypto');
const CryptoJS = require('crypto-js');

const blob = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

function safeAtob(str) {
    try {
        return Buffer.from(str, 'base64').toString('binary');
    } catch (e) {
        return null;
    }
}

function decryptKeyForge(kekStr) {
    let a1 = safeAtob(kekStr);
    let password = safeAtob(a1) || a1;
    try {
        let decrypted = CryptoJS.AES.decrypt(blob, password).toString(CryptoJS.enc.Utf8);
        return decrypted;
    } catch(e) {
        return null;
    }
}

const keys = [
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q=",
    "N3ghQSVEKkctS2FQZFNnVg==",
    "N3glRCpHLUthUGRTZ1YkQA==",
    "@#$%^&*",
    "QCMkJV4mKg"
];

for (let k of keys) {
    console.log("Testing KeyForge with kek:", k);
    let res = decryptKeyForge(k);
    if (res && res.length > 3) console.log("Result:", res);
}