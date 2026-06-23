const crypto = require('crypto');
const fs = require('fs');

const dataB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";
const ivB64 = "ENSHvkGYz2i/T5sS";

const rawData = Buffer.from(dataB64, 'base64');
const iv = Buffer.from(ivB64, 'base64');
const tagLength = 16;

const cipherText = rawData.slice(0, rawData.length - tagLength);
const authTag = rawData.slice(rawData.length - tagLength);

const stringFile = fs.readFileSync('all_js_strings.txt', 'utf8');
const allStrings = stringFile.split('\n').filter(s => s.length >= 5);

// Add the other known strings
allStrings.push("7x!A%D*G-KaPdSgV");
allStrings.push("7x%D*G-KaPdSgV$@");
allStrings.push("ranplDEStAIrCwO5");
allStrings.push("@#$%^&* ");
allStrings.push("auditappkey");

console.log("Starting GCM brute force with provided IV...");

for (let keyStr of allStrings) {
    let keyBufs = [Buffer.from(keyStr)];
    try {
        let b64Buf = Buffer.from(keyStr, 'base64');
        if (b64Buf.length > 5) keyBufs.push(b64Buf);
    } catch(e) {}
    
    for (let keyBuf of keyBufs) {
        if (![16, 24, 32].includes(keyBuf.length)) continue;
        
        let algo = `aes-${keyBuf.length * 8}-gcm`;
        
        try {
            const decipher = crypto.createDecipheriv(algo, keyBuf, iv);
            decipher.setAuthTag(authTag);
            let dec = decipher.update(cipherText, undefined, 'utf8');
            dec += decipher.final('utf8');
            console.log(`SUCCESS GCM! key=${keyStr} Result:`, dec);
            process.exit(0);
        } catch(e) {
            // console.log(`Failed key=${keyStr}: ${e.message}`);
        }
    }
}
console.log("Brute force completed. No success.");
