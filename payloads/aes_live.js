(function () {
  const origApply = Function.prototype.apply;

  Function.prototype.apply = function (ctx, args) {
    try {
      // Detect CryptoJS AES.encrypt call pattern
      if (
        args &&
        args.length >= 3 &&
        args[1] &&
        args[2] &&
        args[2].iv &&
        args[2].mode &&
        args[2].padding
      ) {
        const key = args[1];
        const cfg = args[2];
        const msg = args[0];

        console.group("🔥 AES CALL INTERCEPTED");
        console.log("🔑 KEY (hex):", key?.toString?.());
        console.log("🔑 KEY (utf8):", key?.toString?.(CryptoJS?.enc?.Utf8));
        console.log("🧩 IV (hex):", cfg.iv?.toString?.());
        console.log("📦 PLAINTEXT:", msg?.toString?.());
        console.groupEnd();
      }
    } catch (e) {}

    return origApply.call(this, ctx, args);
  };

  console.log("✅ Global AES interceptor installed. Now login / call API.");

  // Vulscan Dynamic Trigger: Force the page's code object to encrypt something to trigger the hook
  setInterval(() => {
    try {
        if (typeof code !== 'undefined' && code.encryptMessage) {
            code.encryptMessage("vulscan_dynamic_trigger");
        }
    } catch(e) {}
  }, 2000);
})();