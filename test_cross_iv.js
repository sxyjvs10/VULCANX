const CryptoJS = require('crypto-js');
const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const keys = [
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q=",
    "N3ghQSVEKkctS2FQZFNnVg==",
    "N3glRCpHLUthUGRTZ1YkQA==",
    "@#$%^&*",
    "QCMkJV4mKg"
];

let validKeys = [];
for (let k of keys) {
    validKeys.push(CryptoJS.enc.Utf8.parse(k));
    validKeys.push(CryptoJS.enc.Base64.parse(k));
    validKeys.push(CryptoJS.enc.Hex.parse(k));
}

const ivStrs = ["ranplDEStAIrCwO5", ...keys];
let validIvs = [CryptoJS.enc.Hex.parse("00000000000000000000000000000000")];
for (let i of ivStrs) {
    validIvs.push(CryptoJS.enc.Utf8.parse(i));
    validIvs.push(CryptoJS.enc.Base64.parse(i));
}

for (let key of validKeys) {
    if (!key || key.sigBytes === 0) continue;
    
    for (let iv of validIvs) {
        if (!iv || iv.sigBytes === 0) continue;
        
        try {
            let dec = CryptoJS.AES.decrypt(ciphertext, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
            let res = dec.toString(CryptoJS.enc.Utf8);
            if (res && res.length > 5) {
                console.log("SUCCESS CBC:", res);
            }
        } catch(e) {}
        
        try {
            let dec = CryptoJS.AES.decrypt(ciphertext, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
            let res = dec.toString(CryptoJS.enc.Utf8);
            if (res && res.length > 5) {
                console.log("SUCCESS ECB:", res);
            }
        } catch(e) {}
    }
}
