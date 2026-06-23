async function test() {
    const crypto = globalThis.crypto;
    const ciphertextB64 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

    function base64ToArrayBuffer(base64) {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    }

    const keysB64 = [
        "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q=",
        "N3glRCpHLUthUGRTZ1YkQA==",
        "N3ghQSVEKkctS2FQZFNnVg=="
    ];

    const ivsB64 = [
        "ranplDEStAIrCwO5",
        "N3glRCpHLUthUGRTZ1YkQA==",
        "N3ghQSVEKkctS2FQZFNnVg==",
        ""
    ];

    const encryptedData = base64ToArrayBuffer(ciphertextB64);

    for (const keyB64 of keysB64) {
        for (const ivB64 of ivsB64) {
            try {
                const rawKeyBuffer = base64ToArrayBuffer(keyB64);
                // GCM needs exactly the right key size. If key is 16 bytes, it's AES-128. If 32, AES-256.
                // WebCrypto importKey handles 16, 24, 32 bytes automatically for raw AES.
                const aesKeyObject = await crypto.subtle.importKey("raw", rawKeyBuffer, { name: "AES-GCM" }, false, ["decrypt"]);
                
                let iv;
                if (ivB64) {
                    iv = base64ToArrayBuffer(ivB64);
                } else {
                    iv = new Uint8Array(12).buffer; // 12 bytes of 0
                }

                const decryptedData = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKeyObject, encryptedData);
                const decryptedString = new TextDecoder().decode(decryptedData);
                console.log(`SUCCESS AES-GCM! key=${keyB64} iv=${ivB64} result=`, decryptedString);
            } catch (e) {
                // Ignore failure
            }
        }
    }
    console.log("GCM Brute force complete.");
}
test();