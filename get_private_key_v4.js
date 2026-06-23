const fs = require('fs');

function rotDecrypt(str) {
    let res = "";
    for (let i = 0; i < str.length; i++) {
        res += String.fromCharCode(str.charCodeAt(i) - 1);
    }
    return res;
}

const base64 = fs.readFileSync('privateClientBaseEn.txt', 'utf8').trim();
const decoded = Buffer.from(base64, 'base64').toString('utf8');
const decrypted = rotDecrypt(decoded);

const cleanKey = decrypted.replace(/-----BEGIN RSA PRIVATE KEY-----/, "")
                          .replace(/-----END RSA PRIVATE KEY-----/, "")
                          .replace(/\s/g, "");

const formattedKey = "-----BEGIN RSA PRIVATE KEY-----\\n" + 
                     cleanKey.match(/.{1,64}/g).join("\\n") + 
                     "\\n-----END RSA PRIVATE KEY-----\\n";

console.log(formattedKey);
