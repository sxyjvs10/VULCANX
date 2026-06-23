const CryptoJS = require('crypto-js');
const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const keys = [
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q="
];

for (let keyString of keys) {
    let key;
    if (keyString.startsWith("Laej")) {
        key = CryptoJS.enc.Base64.parse(keyString);
    } else {
        key = CryptoJS.enc.Utf8.parse(keyString);
    }
    
    console.log("Testing Key:", keyString);
    let iv1 = key; // for CBC
    
    // ECB
    try {
        let dec = CryptoJS.AES.decrypt(ciphertext, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding });
        console.log("  ECB NoPadding:", dec.toString(CryptoJS.enc.Hex));
    } catch(e) {}
    
    // CBC IV=key
    try {
        let dec = CryptoJS.AES.decrypt(ciphertext, key, { iv: iv1, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding });
        console.log("  CBC NoPadding (IV=key):", dec.toString(CryptoJS.enc.Hex));
    } catch(e) {}
    
    // CBC IV=0
    try {
        let iv0 = CryptoJS.enc.Hex.parse("00000000000000000000000000000000");
        let dec = CryptoJS.AES.decrypt(ciphertext, key, { iv: iv0, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.NoPadding });
        console.log("  CBC NoPadding (IV=0):", dec.toString(CryptoJS.enc.Hex));
    } catch(e) {}
}
