const CryptoJS = require('crypto-js');
const ciphertextB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const rawBytes = CryptoJS.enc.Base64.parse(ciphertextB64);

// Extract first 16 bytes as IV
const iv = CryptoJS.lib.WordArray.create(rawBytes.words.slice(0, 4));

// Extract rest as ciphertext
const cipherWords = rawBytes.words.slice(4);
const cipherText = CryptoJS.lib.WordArray.create(cipherWords, rawBytes.sigBytes - 16);

const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: cipherText });

const keys = [
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q=",
    "N3ghQSVEKkctS2FQZFNnVg==",
    "N3glRCpHLUthUGRTZ1YkQA==",
    "@#$%^&*",
    "QCMkJV4mKg"
];

const modes = [CryptoJS.mode.CFB, CryptoJS.mode.OFB, CryptoJS.mode.CTR];

for (let keyStr of keys) {
    let key = keyStr.length > 20 ? CryptoJS.enc.Base64.parse(keyStr) : CryptoJS.enc.Utf8.parse(keyStr);
    
    for (let mode of modes) {
        try {
            let dec = CryptoJS.AES.decrypt(cipherParams, key, { iv: iv, mode: mode, padding: CryptoJS.pad.NoPadding });
            let text = dec.toString(CryptoJS.enc.Utf8);
            if (text && text.length > 5) {
                let isAscii = true;
                for (let i=0; i<text.length; i++) {
                    if (text.charCodeAt(i) > 127 || text.charCodeAt(i) < 9) {
                        isAscii = false;
                        break;
                    }
                }
                if (isAscii) {
                    console.log(`SUCCESS (Prepended IV) with key ${keyStr} mode ${mode}:`, text);
                }
            }
        } catch(e) {}
    }
}