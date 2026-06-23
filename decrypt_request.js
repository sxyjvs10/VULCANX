const CryptoJS = require('crypto-js');

const encryptedData = "7bsk6cKHHJ5kRNjOOL5kbLnXUpAOA9xr66o5fLR2JSoRtEbjLn6ILhSt+FqZ9zDL";

function decrypt(keyB64) {
    const keyStr = Buffer.from(keyB64, 'base64').toString('utf8');
    console.log("Trying key:", keyStr);

    const Key = CryptoJS.enc.Utf8.parse(keyStr);
    const iv = CryptoJS.enc.Utf8.parse(keyStr);

    try {
        const decrypted = CryptoJS.AES.decrypt(encryptedData, Key, {
            keySize: 128 / 8,
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        }).toString(CryptoJS.enc.Utf8);
        console.log("Decrypted:", decrypted);
    } catch(e) {
        console.log("Error:", e.message);
    }
}

decrypt("N3glRCpHLUthUGRTZ1YkQA==");
decrypt("N3ghQSVEKkctS2FQZFNnVg==");

// The original hardcoded key from worker.js?
// '7x!A%D*G-KaPdSgV' => base64: N3ghQStE*G... wait
// Hex: 3778214125442a472d4b615064536756
function decryptHex(keyHex) {
    const keyStr = Buffer.from(keyHex, 'hex').toString('utf8');
    console.log("Trying hex key:", keyStr);
    const Key = CryptoJS.enc.Utf8.parse(keyStr);
    const iv = CryptoJS.enc.Utf8.parse(keyStr);

    try {
        const decrypted = CryptoJS.AES.decrypt(encryptedData, Key, {
            keySize: 128 / 8,
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        }).toString(CryptoJS.enc.Utf8);
        console.log("Decrypted:", decrypted);
    } catch(e) {
        console.log("Error:", e.message);
    }
}
decryptHex("3778214125442a472d4b615064536756");