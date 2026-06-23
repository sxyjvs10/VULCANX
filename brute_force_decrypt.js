const CryptoJS = require('crypto-js');

const ciphertext = "ZepoYhfaD7e0+JNzWEHaJXNH5FwXrVSiQqRWWO1GuOs=";

const keys = [
    "7x%D*G-KaPdSgV$@",
    "7x!A%D*G-KaPdSgV",
    "912170bec8952371503030303030303030303030303030303030303030303030" // Jus Key Hex
];

function attempt(key, iv, modeName, mode, padding) {
    try {
        let dec = CryptoJS.AES.decrypt(ciphertext, key, {
            iv: iv,
            mode: mode,
            padding: padding
        });
        let result = dec.toString(CryptoJS.enc.Utf8);
        if (result && /^[\x20-\x7E]+$/.test(result)) {
            console.log(`[+] SUCCESS!`);
            console.log(`    Mode: ${modeName}`);
            console.log(`    Key: ${key.toString()}`);
            console.log(`    IV: ${iv ? iv.toString() : 'None'}`);
            console.log(`    Result: ${result}`);
            return true;
        }
    } catch (e) {}
    return false;
}

for (let kStr of keys) {
    let key;
    if (kStr.length > 32) {
        key = CryptoJS.enc.Hex.parse(kStr);
    } else {
        key = CryptoJS.enc.Utf8.parse(kStr);
    }

    const ivs = [
        key, // Often IV=Key
        CryptoJS.enc.Hex.parse("00000000000000000000000000000000"), // Zero IV
        CryptoJS.enc.Utf8.parse(kStr.substring(0, 16)),
        null
    ];

    const modes = [
        { name: "CBC", val: CryptoJS.mode.CBC },
        { name: "ECB", val: CryptoJS.mode.ECB }
    ];

    const paddings = [
        CryptoJS.pad.Pkcs7,
        CryptoJS.pad.NoPadding
    ];

    for (let modeObj of modes) {
        for (let pad of paddings) {
            for (let iv of ivs) {
                if (attempt(key, iv, modeObj.name, modeObj.val, pad)) break;
            }
        }
    }
}
