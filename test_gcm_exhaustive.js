const crypto = require('crypto');
const ciphertextB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";
const rawBytes = Buffer.from(ciphertextB64, 'base64');
const tagLength = 16;
if (rawBytes.length <= tagLength) process.exit(0);

const cipherText = rawBytes.slice(0, rawBytes.length - tagLength);
const authTag = rawBytes.slice(rawBytes.length - tagLength);

const keys = [
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q=",
    "N3ghQSVEKkctS2FQZFNnVg==",
    "N3glRCpHLUthUGRTZ1YkQA==",
    "ranplDEStAIrCwO5",
    "@#$%^&*",
    "QCMkJV4mKg"
];

const ivs = keys;

for (let keyStr of keys) {
    let keyBuf = Buffer.from(keyStr);
    
    // AES-GCM requires key to be 16, 24, or 32 bytes
    let validKeys = [];
    if (keyBuf.length === 16 || keyBuf.length === 24 || keyBuf.length === 32) validKeys.push(keyBuf);
    
    let b64Buf = Buffer.from(keyStr, 'base64');
    if (b64Buf.length === 16 || b64Buf.length === 24 || b64Buf.length === 32) validKeys.push(b64Buf);

    for (let key of validKeys) {
        let algo = `aes-${key.length * 8}-gcm`;
        
        for (let ivStr of ivs) {
            let ivsToTest = [Buffer.from(ivStr), Buffer.from(ivStr, 'base64'), Buffer.alloc(12, 0)];
            for (let iv of ivsToTest) {
                try {
                    const decipher = crypto.createDecipheriv(algo, key, iv);
                    decipher.setAuthTag(authTag);
                    let dec = decipher.update(cipherText, undefined, 'utf8');
                    dec += decipher.final('utf8');
                    console.log(`SUCCESS GCM! key=${keyStr} iv=${ivStr} Result:`, dec);
                } catch(e) {}
            }
        }
    }
}
