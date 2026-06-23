const crypto = require('crypto');
const fs = require('fs');

const privateKey = fs.readFileSync('private_key_v3.pem', 'utf8').trim();

const encryptedKeyB64 = "SV6rJpAPxuOx8r6TgXVsttnJUIj4NVTwexWzkOLzLgQzyj0usGWzQSVArwC44j1uEyGWPnTE9mreij5oM0EE7DhtHZVomUQWd1aHuM3gg6zOdD5JvdLzugzCmpC4OPFF23O3rvapQi5TvCTg7AMhJQogTWrZDy5HJuWhuTT3GlqbFQsM5PHTWFo1YHfP6lsYqAL0DxG8ovoUqxQDtbD7lYjUpoAA18iOs0tc7zKknDLlN8cb6wTZ7cZV/lotO1NwPUhCM6oQL/l0bCdJ7CNcOWzLf5r+/NrYwx+lVARiIMwY8gd3MhLwsytjWS96C+P3SfUdLJzUOZXQSWDCAzRUcg==";
const ivB64 = "ENSHvkGYz2i/T5sS";
const dataB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

async function run() {
    try {
        // Step 1: Decrypt AES key with RSA-OAEP
        const encryptedKey = Buffer.from(encryptedKeyB64, 'base64');
        const aesKeyBuffer = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            encryptedKey
        );
        
        console.log("Decrypted AES Key (Hex):", aesKeyBuffer.toString('hex'));
        console.log("Decrypted AES Key (B64):", aesKeyBuffer.toString('base64'));

        // Step 2: Decrypt Data with AES-GCM
        const iv = Buffer.from(ivB64, 'base64');
        const rawData = Buffer.from(dataB64, 'base64');
        const tagLength = 16;
        const cipherText = rawData.slice(0, rawData.length - tagLength);
        const authTag = rawData.slice(rawData.length - tagLength);

        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKeyBuffer, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(cipherText, undefined, 'utf8');
        decrypted += decipher.final('utf8');

        console.log("\nFINAL DECRYPTED DATA:");
        console.log(decrypted);

    } catch (e) {
        console.error("Error during decryption:", e.message);
    }
}

run();
