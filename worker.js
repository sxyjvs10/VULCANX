// src/app/shield/helpers/service/crypto.worker.ts
var aesKey = null;
var keyTimeout = null;
var KEY_TTL = 5 * 60 * 1e3;
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
async function importRSAPublicKey(pemKey) {
  const pemContents = pemKey.replace(/-----BEGIN PUBLIC KEY-----/, "").replace(/-----END PUBLIC KEY-----/, "").replace(/\s/g, "");
  const binaryDer = base64ToArrayBuffer(pemContents);
  return crypto.subtle.importKey(
    "spki",
    binaryDer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}
async function importRSAPrivateKey(pemKey) {
  const pemContents = pemKey.replace(/-----BEGIN PRIVATE KEY-----/, "").replace(/-----END PRIVATE KEY-----/, "").replace(/\s/g, "");
  const binaryDer = base64ToArrayBuffer(pemContents);
  return crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );
}
async function generateAESKey() {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}
function scheduleKeyDestruction() {
  if (keyTimeout) clearTimeout(keyTimeout);
  keyTimeout = setTimeout(() => {
    aesKey = null;
  }, KEY_TTL);
}
async function encryptData(plaintext, rsaPublicKeyPem) {
  try {
    if (!aesKey) {
      aesKey = await generateAESKey();
      scheduleKeyDestruction();
    }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedText = new TextEncoder().encode(plaintext);
    const rawKey = await crypto.subtle.exportKey("raw", aesKey);
    const base64Key = arrayBufferToBase64(rawKey);
    const encryptedData = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      encodedText
    );
    const exportedKey = await crypto.subtle.exportKey("raw", aesKey);
    const rsaPublicKey = await importRSAPublicKey(rsaPublicKeyPem);
    const encryptedKey = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      rsaPublicKey,
      exportedKey
    );
    return {
      encryptedKey: arrayBufferToBase64(encryptedKey),
      iv: arrayBufferToBase64(iv.buffer),
      data: arrayBufferToBase64(encryptedData)
    };
  } catch (error) {
    throw new Error(`Encryption failed: ${error.message}`);
  }
}
async function decryptData(encryptedKeyB64, ivB64, dataB64, rsaPrivateKeyPem) {
  try {
    const rsaPrivateKey = await importRSAPrivateKey(rsaPrivateKeyPem);
    const encryptedKey = base64ToArrayBuffer(encryptedKeyB64);
    const aesKeyBuffer = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      rsaPrivateKey,
      encryptedKey
    );
    const aesKey2 = await crypto.subtle.importKey(
      "raw",
      aesKeyBuffer,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    const iv = base64ToArrayBuffer(ivB64);
    const encryptedData = base64ToArrayBuffer(dataB64);
    const decryptedData = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey2,
      encryptedData
    );
    return new TextDecoder().decode(decryptedData);
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}
async function decryptResponseData(dataB64, ivB64) {
  try {
    if (!aesKey) {
      throw new Error("AES key has expired or was never generated.");
    }
    const iv = base64ToArrayBuffer(ivB64);
    const encryptedData = base64ToArrayBuffer(dataB64);
    const decryptedData = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      encryptedData
    );
    return new TextDecoder().decode(decryptedData);
  } catch (error) {
    throw new Error(`Response decryption failed: ${error.message}`);
  }
}
addEventListener("message", async ({ data }) => {
  try {
    switch (data.action) {
      case "encrypt": {
        const result = await encryptData(data.plaintext, data.rsaPublicKey);
        postMessage({ success: true, result });
        break;
      }
      case "decrypt": {
        const result = await decryptData(
          data.encryptedKey,
          data.iv,
          data.data,
          data.rsaPrivateKey
        );
        postMessage({ success: true, result });
        break;
      }
      case "destroy": {
        aesKey = null;
        if (keyTimeout) clearTimeout(keyTimeout);
        postMessage({ success: true });
        break;
      }
      case "decryptResponse": {
        const result = await decryptResponseData(data.data, data.iv);
        postMessage({ success: true, result });
        break;
      }
    }
  } catch (error) {
    postMessage({ success: false, error: error.message });
  }
});
