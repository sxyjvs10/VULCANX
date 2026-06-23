const crypto = require('crypto');

const ciphertextB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";
const rawBytes = Buffer.from(ciphertextB64, 'base64');

const iv12 = rawBytes.slice(0, 12);
const tag16 = rawBytes.slice(rawBytes.length - 16);
const cipherGCM = rawBytes.slice(12, rawBytes.length - 16);

const keys = [
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    "TMP190729142821542PK5XHYR1T4L43W",
    "TMP190729191429620D4C271BEE9ZCG9",
    "TMP190731163234904MFLJU9C2GCUMK3",
    "@#$%^&*",
    "auditappkey"
];

console.log("Testing GCM with prepended 12-byte IV...");
for (let keyStr of keys) {
    let key = Buffer.from(keyStr);
    
    // Adjust key size if needed
    let key32 = Buffer.alloc(32, 0);
    key.copy(key32);
    
    let key16 = Buffer.alloc(16, 0);
    key.copy(key16);

    for (let k of [key, key16, key32]) {
        if (![16, 24, 32].includes(k.length)) continue;
        let algo = `aes-${k.length * 8}-gcm`;
        try {
            const decipher = crypto.createDecipheriv(algo, k, iv12);
            decipher.setAuthTag(tag16);
            let decrypted = decipher.update(cipherGCM, undefined, 'utf8');
            decrypted += decipher.final('utf8');
            console.log(`SUCCESS GCM! key=${keyStr} length=${k.length}:`, decrypted);
        } catch(e) {}
    }
}
