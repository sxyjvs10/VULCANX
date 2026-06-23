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

const ciphers = [CryptoJS.AES, CryptoJS.DES, CryptoJS.TripleDES, CryptoJS.RC4, CryptoJS.Rabbit];
const modes = [CryptoJS.mode.CBC, CryptoJS.mode.ECB, CryptoJS.mode.CFB, CryptoJS.mode.OFB, CryptoJS.mode.CTR];
const paddings = [CryptoJS.pad.Pkcs7, CryptoJS.pad.ZeroPadding, CryptoJS.pad.NoPadding];

for (let keyStr of keys) {
    let keyUtf8 = CryptoJS.enc.Utf8.parse(keyStr);
    let keyB64 = CryptoJS.enc.Base64.parse(keyStr);
    let keyHex = CryptoJS.enc.Hex.parse(keyStr);

    let keyVariants = [keyUtf8, keyB64, keyHex, keyStr];

    for (let keyVar of keyVariants) {
        if (!keyVar || (keyVar.sigBytes !== undefined && keyVar.sigBytes === 0)) continue;

        let ivs = [keyVar, CryptoJS.enc.Utf8.parse("ranplDEStAIrCwO5"), CryptoJS.enc.Hex.parse("00000000000000000000000000000000")];

        for (let iv of ivs) {
            for (let cipher of ciphers) {
                for (let mode of modes) {
                    for (let pad of paddings) {
                        try {
                            let options = { mode: mode, padding: pad };
                            if (cipher !== CryptoJS.RC4 && cipher !== CryptoJS.Rabbit) {
                                options.iv = iv;
                            }
                            let dec = cipher.decrypt(ciphertext, keyVar, options);
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
                                    console.log(`SUCCESS! key=${keyStr}`);
                                    console.log("Result:", text);
                                }
                            }
                        } catch (e) {}
                    }
                }
            }
        }
    }
}