const fs = require('fs');

function rotDecrypt(str) {
    let res = "";
    for (let i = 0; i < str.length; i++) {
        res += String.fromCharCode(str.charCodeAt(i) - 1);
    }
    return res;
}

const base64 = fs.readFileSync('bigPriBaseEn.txt', 'utf8').trim();
const decoded = Buffer.from(base64, 'base64').toString('utf8');
console.log(rotDecrypt(decoded));
