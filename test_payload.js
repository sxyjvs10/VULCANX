async function test() {
    const crypto = globalThis.crypto;
    const myBase64AesKey = "LaejUdxAsOr5k6BCxuRYqeqM3TKplhlMsdxbpeT4I5Q=";
    const ivB64 = "ranplDEStAIrCwO5";
    // First, test their payload
    const dataB64_1 = "TEbAoVmGpvQymmQt2kHs3AKCuJ1s07+0/SNCU3G+QMlx3LBlPlR4aSMMMVQKsSG9riZbFwOvZEezQw5fV8Ho2fuF5HegrU1Fg2ts3cFa3wJGI84E0JaT/DTzsUkB/268og46tKmO5Sbh4G8NteHvQjh88pk6CG80X6qo49QtmA==";
    
    // User's payload
    const dataB64_2 = "EQXG4Pg7Nw+MAR9MvLleLH/X4SgpDFbctaQH8kJ5B/B5KYZm7B5JucP4z2jQXn0lKI296UZESAMcO/OkL7548MDYQHXWlbMWvTIXFNRbDBeXy+TmhVn7V96oTw==";

    function base64ToArrayBuffer(base64) {
      const binary = atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    }

    try {
      const rawKeyBuffer = base64ToArrayBuffer(myBase64AesKey);
      const aesKeyObject = await crypto.subtle.importKey("raw", rawKeyBuffer, { name: "AES-GCM" }, false, ["decrypt"]);
      const iv = base64ToArrayBuffer(ivB64);
      
      try {
          const encryptedData1 = base64ToArrayBuffer(dataB64_1);
          const decryptedData1 = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKeyObject, encryptedData1);
          const decryptedString1 = new TextDecoder().decode(decryptedData1);
          console.log("Original Payload Decrypted:", decryptedString1);
      } catch (e) {
          console.log("Original payload error:", e.message);
      }

      try {
          const encryptedData2 = base64ToArrayBuffer(dataB64_2);
          const decryptedData2 = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKeyObject, encryptedData2);
          const decryptedString2 = new TextDecoder().decode(decryptedData2);
          console.log("User Payload Decrypted:", decryptedString2);
      } catch (e) {
          console.log("User payload error:", e.message);
      }

    } catch (error) {
      console.log("Key import error:", error);
    }
}
test();