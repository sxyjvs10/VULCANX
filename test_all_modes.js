const CryptoJS = require('crypto-js');
const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const keys = [
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q="
];

const ivs = [
    "ranplDEStAIrCwO5",
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    ""
];

const modes = [CryptoJS.mode.CBC, CryptoJS.mode.CFB, CryptoJS.mode.CTR, CryptoJS.mode.OFB, CryptoJS.mode.ECB];

for (let keyStr of keys) {
    let key = keyStr.startsWith("Laej") ? CryptoJS.enc.Base64.parse(keyStr) : CryptoJS.enc.Utf8.parse(keyStr);
    
    for (let ivStr of ivs) {
        let iv = ivStr ? CryptoJS.enc.Utf8.parse(ivStr) : CryptoJS.enc.Hex.parse("00000000000000000000000000000000");
        
        for (let mode of modes) {
            try {
                let dec = CryptoJS.AES.decrypt(ciphertext, key, { iv: iv, mode: mode, padding: CryptoJS.pad.NoPadding });
                let text = dec.toString(CryptoJS.enc.Utf8);
                // Check if it's printable ascii
                if (text && /^[\x20-\x7E]*$/.test(text) && text.length > 10) {
                    console.log(`SUCCESS [${mode}] key=${keyStr} iv=${ivStr}:`, text);
                }
            } catch(e) {}
        }
    }
}
