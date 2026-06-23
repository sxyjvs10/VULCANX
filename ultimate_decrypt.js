const crypto = require('crypto');
const fs = require('fs');

const encryptedKeyB64 = "SV6rJpAPxuOx8r6TgXVsttnJUIj4NVTwexWzkOLzLgQzyj0usGWzQSVArwC44j1uEyGWPnTE9mreij5oM0EE7DhtHZVomUQWd1aHuM3gg6zOdD5JvdLzugzCmpC4OPFF23O3rvapQi5TvCTg7AMhJQogTWrZDy5HJuWhuTT3GlqbFQsM5PHTWFo1YHfP6lsYqAL0DxG8ovoUqxQDtbD7lYjUpoAA18iOs0tc7zKknDLlN8cb6wTZ7cZV/lotO1NwPUhCM6oQL/l0bCdJ7CNcOWzLf5r+/NrYwx+lVARiIMwY8gd3MhLwsytjWS96C+P3SfUdLJzUOZXQSWDCAzRUcg==";
const ivB64 = "ENSHvkGYz2i/T5sS";
const dataB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

const priKeys = [
    'private_key_v3.pem',
    'private_key_v5.pem'
];

async function run() {
    const encryptedKey = Buffer.from(encryptedKeyB64, 'base64');
    const iv = Buffer.from(ivB64, 'base64');
    const rawData = Buffer.from(dataB64, 'base64');
    const tagLength = 16;
    const cipherText = rawData.slice(0, rawData.length - tagLength);
    const authTag = rawData.slice(rawData.length - tagLength);

    for (let keyFile of priKeys) {
        if (!fs.existsSync(keyFile)) continue;
        const privateKey = fs.readFileSync(keyFile, 'utf8').trim();
        
        for (let hash of ["sha256", "sha1"]) {
            try {
                const aesKeyBuffer = crypto.privateDecrypt(
                    {
                        key: privateKey,
                        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                        oaepHash: hash,
                        mgf1Hash: hash
                    },
                    encryptedKey
                );
                
                console.log(`\n[+] SUCCESS RSA Decrypt! KeyFile=${keyFile}, Hash=${hash}`);
                console.log("Decrypted AES Key (B64):", aesKeyBuffer.toString('base64'));

                const decipher = crypto.createDecipheriv('aes-256-gcm', aesKeyBuffer, iv);
                decipher.setAuthTag(authTag);
                let decrypted = decipher.update(cipherText, undefined, 'utf8');
                decrypted += decipher.final('utf8');

                console.log("FINAL DECRYPTED DATA:");
                console.log(decrypted);
                return;
            } catch (err) {
                // console.log(`[-] Failed RSA Decrypt: KeyFile=${keyFile}, Hash=${hash}: ${err.message}`);
            }
        }
    }
    console.log("\n[-] All decryption attempts failed.");
}

run();
