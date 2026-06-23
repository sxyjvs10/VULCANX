const CryptoJS = require('crypto-js');
const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const keys = ["7x!A%D*G-KaPdSgV", "7x%D*G-KaPdSgV$@", "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q="];
const ivs = ["ranplDEStAIrCwO5", "7x!A%D*G-KaPdSgV", "7x%D*G-KaPdSgV$@", ""];

for (let keyString of keys) {
    let key;
    if (keyString.length > 20) {
        key = CryptoJS.enc.Base64.parse(keyString);
    } else {
        key = CryptoJS.enc.Utf8.parse(keyString);
    }
    
    for (let ivString of ivs) {
        let iv;
        if (ivString) iv = CryptoJS.enc.Utf8.parse(ivString);
        else iv = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");

        try {
            const dec1 = CryptoJS.AES.decrypt(ciphertext, key, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });
            const text = dec1.toString(CryptoJS.enc.Utf8);
            if (text) console.log(`SUCCESS CBC (key=${keyString}, iv=${ivString}):`, text);
        } catch (e) {}
    }
}
