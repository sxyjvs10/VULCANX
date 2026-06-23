const crypto = require('crypto');

const ciphertextB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";
const rawBytes = Buffer.from(ciphertextB64, 'base64');
const tagLength = 16;

const iv = Buffer.from("ranplDEStAIrCwO5", 'base64');

const keys = [
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q=",
    "N3ghQSVEKkctS2FQZFNnVg==",
    "N3glRCpHLUthUGRTZ1YkQA==",
    "@#$%^&*",
    "auditappkey"
];

console.log("Testing GCM with fixed IV (ranplDEStAIrCwO5)...");
for (let keyStr of keys) {
    let keyBufs = [Buffer.from(keyStr)];
    try {
        let b64Buf = Buffer.from(keyStr, 'base64');
        if (b64Buf.length > 5) keyBufs.push(b64Buf);
    } catch(e) {}
    
    for (let key of keyBufs) {
        if (![16, 24, 32].includes(key.length)) continue;
        let algo = `aes-${key.length * 8}-gcm`;
        
        try {
            const decipher = crypto.createDecipheriv(algo, key, iv);
            decipher.setAuthTag(rawBytes.slice(rawBytes.length - 16));
            let decrypted = decipher.update(rawBytes.slice(0, rawBytes.length - 16), undefined, 'utf8');
            decrypted += decipher.final('utf8');
            console.log(`SUCCESS GCM! key=${keyStr}:`, decrypted);
        } catch(e) {}
    }
}
