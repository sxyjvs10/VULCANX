const crypto = require('crypto');

const ciphertextB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";
const keyB64 = "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q=";
const ivB64 = "ranplDEStAIrCwO5";

const key = Buffer.from(keyB64, 'base64');
const iv = Buffer.from(ivB64, 'base64');
const encryptedData = Buffer.from(ciphertextB64, 'base64');

// For AES-GCM in Node, the auth tag is the last 16 bytes of the ciphertext.
const tagLength = 16;
if (encryptedData.length <= tagLength) {
    console.log("Ciphertext too short for GCM.");
} else {
    const ciphertext = encryptedData.slice(0, encryptedData.length - tagLength);
    const authTag = encryptedData.slice(encryptedData.length - tagLength);

    try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(ciphertext, undefined, 'utf8');
        decrypted += decipher.final('utf8');
        console.log("AES-GCM Decrypted:", decrypted);
    } catch(e) {
        console.log("AES-GCM Error:", e.message);
    }
}
