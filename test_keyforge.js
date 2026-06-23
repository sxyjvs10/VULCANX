const CryptoJS = require('crypto-js');
const ciphertext = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

// The KeyForge decryption process in keyforge.py:
// 1. Decode KEK (atob)
// 2. Decode KEK again (atob^2) to get password
// 3. Decrypt Blob using Password
// BUT what if the key is just 7x!A%D*G-KaPdSgV?

const k1 = "7x!A%D*G-KaPdSgV";

// The mahofin strategy says:
// var numericParts = [7348625, 9816254, 5271843];
// let's try the key forge
