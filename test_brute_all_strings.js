const CryptoJS = require('crypto-js');
const fs = require('fs');
const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const strings = fs.readFileSync('all_js_strings.txt', 'utf8').split('\n');

for (let keyStr of strings) {
    if (!keyStr) continue;
    let key = CryptoJS.enc.Utf8.parse(keyStr);
    try {
        let dec = CryptoJS.AES.decrypt(ciphertext, key, { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.Pkcs7 });
        let text = dec.toString(CryptoJS.enc.Utf8);
        if (text && /^[\\x20-\\x7E]*$/.test(text) && text.length > 5) {
            console.log(`SUCCESS ECB! key=${keyStr}`);
            console.log("Result:", text);
            process.exit(0);
        }
    } catch(e) {}
    
    // Test CBC with iv=key
    try {
        let dec = CryptoJS.AES.decrypt(ciphertext, key, { iv: key, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
        let text = dec.toString(CryptoJS.enc.Utf8);
        if (text && /^[\\x20-\\x7E]*$/.test(text) && text.length > 5) {
            console.log(`SUCCESS CBC! key=${keyStr}`);
            console.log("Result:", text);
            process.exit(0);
        }
    } catch(e) {}
}
console.log("Brute force finished.");
