const crypto = require('crypto');
const fs = require('fs');

const ciphertextB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";
const rawBytes = Buffer.from(ciphertextB64, 'base64');
const tagLength = 16;

const hardcodedIvs = [
    "ranplDEStAIrCwO5",
    "7x!A%D*G-KaPdSgV",
    "7x%D*G-KaPdSgV$@",
    "@#$%^&*",
    "QCMkJV4mKg"
];

const stringFile = fs.readFileSync('all_js_strings.txt', 'utf8');
const allStrings = stringFile.split('\n').filter(s => s.length >= 5);

console.log("Starting exhaustive GCM brute force...");

for (let keyStr of allStrings) {
    let keyBufs = [Buffer.from(keyStr)];
    try {
        let b64Buf = Buffer.from(keyStr, 'base64');
        if (b64Buf.length > 5) keyBufs.push(b64Buf);
    } catch(e) {}
    
    for (let keyBuf of keyBufs) {
        if (![16, 24, 32].includes(keyBuf.length)) continue;
        
        let algo = `aes-${keyBuf.length * 8}-gcm`;
        
        // Test hardcoded IVs (if they match the required lengths, or padded? GCM accepts any IV length, usually 12)
        for (let ivStr of hardcodedIvs) {
            let ivBuf = Buffer.from(ivStr);
            try {
                let cipherText = rawBytes.slice(0, rawBytes.length - tagLength);
                let authTag = rawBytes.slice(rawBytes.length - tagLength);
                
                const decipher = crypto.createDecipheriv(algo, keyBuf, ivBuf);
                decipher.setAuthTag(authTag);
                let dec = decipher.update(cipherText, undefined, 'utf8');
                dec += decipher.final('utf8');
                console.log(`SUCCESS GCM (hardcoded IV)! key=${keyStr} iv=${ivStr} Result:`, dec);
                process.exit(0);
            } catch(e) {}
        }
        
        // Test 12-byte prepended IV
        try {
            let iv12 = rawBytes.slice(0, 12);
            let cipherText = rawBytes.slice(12, rawBytes.length - tagLength);
            let authTag = rawBytes.slice(rawBytes.length - tagLength);
            
            const decipher = crypto.createDecipheriv(algo, keyBuf, iv12);
            decipher.setAuthTag(authTag);
            let dec = decipher.update(cipherText, undefined, 'utf8');
            dec += decipher.final('utf8');
            console.log(`SUCCESS GCM (12-byte prepended IV)! key=${keyStr} Result:`, dec);
            process.exit(0);
        } catch(e) {}
        
        // Test 16-byte prepended IV
        try {
            let iv16 = rawBytes.slice(0, 16);
            let cipherText = rawBytes.slice(16, rawBytes.length - tagLength);
            let authTag = rawBytes.slice(rawBytes.length - tagLength);
            
            const decipher = crypto.createDecipheriv(algo, keyBuf, iv16);
            decipher.setAuthTag(authTag);
            let dec = decipher.update(cipherText, undefined, 'utf8');
            dec += decipher.final('utf8');
            console.log(`SUCCESS GCM (16-byte prepended IV)! key=${keyStr} Result:`, dec);
            process.exit(0);
        } catch(e) {}
    }
}
console.log("Brute force completed. No success.");
