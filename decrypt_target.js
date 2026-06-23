const CryptoJS = require('crypto-js');

const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const k1 = Buffer.from("N3glRCpHLUthUGRTZ1YkQA==", 'base64').toString('utf8');
const k2 = Buffer.from("N3ghQSVEKkctS2FQZFNnVg==", 'base64').toString('utf8');

console.log("k1:", k1);
console.log("k2:", k2);

const keys = [k1, k2];
const ivs = [k1, k2, "0000000000000000", ""];

for (let keyStr of keys) {
    let key = CryptoJS.enc.Utf8.parse(keyStr);
    for (let ivStr of ivs) {
        let iv;
        if (ivStr) {
             iv = CryptoJS.enc.Utf8.parse(ivStr);
        } else {
             iv = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");
        }
        
        try {
            let dec = CryptoJS.AES.decrypt(ciphertext, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
            let result = dec.toString(CryptoJS.enc.Utf8);
            if (result) console.log(`CBC Decrypted with key=${keyStr} iv=${ivStr}:`, result);
        } catch(e) {}
    }
    
    try {
        let dec = CryptoJS.AES.decrypt(ciphertext, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
        let result = dec.toString(CryptoJS.enc.Utf8);
        if (result) console.log(`ECB Decrypted with key=${keyStr}:`, result);
    } catch(e) {}
}

