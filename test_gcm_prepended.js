const crypto = require('crypto');

const ciphertextB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";
const rawBytes = Buffer.from(ciphertextB64, 'base64');

const keys = [
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    Buffer.from("LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q=", 'base64')
];

// Test if first 12 bytes are IV
const iv12 = rawBytes.slice(0, 12);
const tag16 = rawBytes.slice(rawBytes.length - 16);
const cipherGCM = rawBytes.slice(12, rawBytes.length - 16);

console.log("Testing GCM with prepended 12-byte IV...");
for (let key of keys) {
    try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', typeof key === 'string' ? Buffer.from(key) : key, iv12);
        decipher.setAuthTag(tag16);
        let decrypted = decipher.update(cipherGCM, undefined, 'utf8');
        decrypted += decipher.final('utf8');
        console.log("SUCCESS GCM (IV prepended):", decrypted);
    } catch(e) {}
    
    // Also try AES-128-GCM if key is 16 bytes
    if (key.length === 16) {
        try {
            const decipher = crypto.createDecipheriv('aes-128-gcm', typeof key === 'string' ? Buffer.from(key) : key, iv12);
            decipher.setAuthTag(tag16);
            let decrypted = decipher.update(cipherGCM, undefined, 'utf8');
            decrypted += decipher.final('utf8');
            console.log("SUCCESS AES-128-GCM (IV prepended):", decrypted);
        } catch(e) {}
    }
}
