const crypto = require('crypto');
const fs = require('fs');

try {
    const pub = fs.readFileSync('target_pub.pem', 'utf8');
    const key = crypto.createPublicKey(pub);
    console.log("Parsed successfully!");
    console.log(key.export({ type: 'spki', format: 'pem' }));
} catch(e) {
    console.error("Error parsing target_pub.pem:", e.message);
}
