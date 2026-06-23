(function () {
    console.log("✅ VULSCAN: Global Interceptor Loaded.");

    // =================================================================================
    // 1. CryptoJS AES Hook (Original)
    // =================================================================================
    const origApply = Function.prototype.apply;
    Function.prototype.apply = function (ctx, args) {
        try {
            if (args && args.length >= 2 && args[1] && args[1].key && args[1].iv) { // AES Decrypt
                 console.group("🔥 CryptoJS AES DECRYPT Intercepted");
                 console.log("🔑 KEY:", args[1].key.toString(CryptoJS.enc.Hex));
                 console.log("🧩 IV:", args[1].iv.toString(CryptoJS.enc.Hex));
                 console.log("📦 CIPHERTEXT:", args[0]);
                 console.groupEnd();
            } else if (args && args.length >= 3 && args[1] && args[2] && args[2].iv && args[2].mode && args[2].padding) { // AES Encrypt
                const key = args[1];
                const cfg = args[2];
                const msg = args[0];
                console.group("🔥 CryptoJS AES ENCRYPT Intercepted");
                console.log("🔑 KEY (hex):", key?.toString?.());
                console.log("🔑 KEY (utf8):", key?.toString?.(CryptoJS.enc.Utf8));
                console.log("🧩 IV (hex):", cfg.iv?.toString?.());
                console.log("📦 PLAINTEXT:", msg?.toString?.());
                console.groupEnd();
            }
        } catch (e) { /* ignore */ }
        return origApply.call(this, ctx, args);
    };

    // =================================================================================
    // 2. Web Crypto API Hook (Modern & Standard)
    // =================================================================================
    if (window.crypto && window.crypto.subtle) {
        const origEncrypt = window.crypto.subtle.encrypt;
        window.crypto.subtle.encrypt = function (...args) {
            try {
                const algorithm = args[0];
                const key = args[1];
                const data = args[2];
                console.group("🔥 WebCrypto ENCRYPT Intercepted");
                console.log("🛡️ ALGORITHM:", algorithm);
                console.log("🔑 KEY (raw):", key);
                // Try to export the key to see its raw value
                window.crypto.subtle.exportKey('raw', key).then(rawKey => {
                     console.log("🔑 KEY (exported):", new Uint8Array(rawKey));
                }).catch(()=>{});
                console.log("📦 PLAINTEXT (raw):", new Uint8Array(data));
                console.groupEnd();
            } catch (e) { /* ignore */ }
            return origEncrypt.apply(this, args);
        };

        const origDecrypt = window.crypto.subtle.decrypt;
        window.crypto.subtle.decrypt = function (...args) {
            try {
                const algorithm = args[0];
                const key = args[1];
                const data = args[2];
                console.group("🔥 WebCrypto DECRYPT Intercepted");
                console.log("🛡️ ALGORITHM:", algorithm);
                 console.log("🔑 KEY (raw):", key);
                window.crypto.subtle.exportKey('raw', key).then(rawKey => {
                     console.log("🔑 KEY (exported):", new Uint8Array(rawKey));
                }).catch(()=>{});
                console.log("📦 CIPHERTEXT (raw):", new Uint8Array(data));
                console.groupEnd();
            } catch (e) { /* ignore */ }
            return origDecrypt.apply(this, args);
        };
        console.log("✅ VULSCAN: WebCrypto Hooks installed.");
    }

    // =================================================================================
    // 3. Generic Function Hooker (Heuristic-based)
    // =================================================================================
    // Look for functions with names suggesting encryption/decryption
    // and hook them to log arguments.
    setTimeout(() => {
        console.log("[*] VULSCAN: Starting generic function hook analysis...");
        const keywords = ['encrypt', 'decrypt', 'cipher', 'decode', 'encode', 'aes', 'des', 'rsa'];
        const seenFunctions = new Set();

        for (const prop in window) {
            try {
                if (typeof window[prop] === 'object' && window[prop] !== null) {
                    for (const subProp in window[prop]) {
                        if (typeof window[prop][subProp] === 'function') {
                            const funcName = subProp.toLowerCase();
                            if (keywords.some(k => funcName.includes(k)) && !seenFunctions.has(window[prop][subProp])) {
                                const origFunc = window[prop][subProp];
                                seenFunctions.add(origFunc);

                                window[prop][subProp] = function(...args) {
                                    console.group(`🔥 Generic Hook: Function "${prop}.${subProp}" called!`);
                                    try {
                                        console.log("ARGUMENTS:", args);
                                        // Attempt to find keys/data based on common patterns
                                        args.forEach((arg, i) => {
                                            if (typeof arg === 'string' && arg.length > 10) console.log(`  [Arg ${i} is a long string]:`, arg);
                                            if (arg && arg.iv) console.log(`  [Arg ${i} has an IV]:`, arg.iv.toString());
                                            if (arg && arg.key) console.log(`  [Arg ${i} has a key]:`, arg.key.toString());
                                        });
                                    } catch(e) {}
                                    console.groupEnd();
                                    return origFunc.apply(this, args);
                                };
                                console.log(`  [+] Hooked potential crypto function: window.${prop}.${subProp}`);
                            }
                        }
                    }
                }
            } catch (e) { /* ignore */ }
        }
        console.log("[*] VULSCAN: Generic hook analysis complete.");
    }, 3000); // Run after a delay to let the page load

})();
