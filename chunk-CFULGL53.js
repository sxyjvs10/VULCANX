import {
  require_crypto_js
} from "./chunk-U4FAYTJH.js";
import {
  environment
} from "./chunk-L5HWXGQY.js";
import {
  HttpHeaders,
  Injectable,
  __async,
  __toESM,
  init_esm2015,
  setClassMetadata,
  throwError,
  ɵɵdefineInjectable
} from "./chunk-DMFUQV5T.js";

// src/app/shield/helpers/service/shield.service.ts
var CryptoJS = __toESM(require_crypto_js());
init_esm2015();
var ShieldService = class _ShieldService {
  constructor() {
    this.apiVer = environment.apiVersion;
    this.httpOptions = { headers: new HttpHeaders({}) };
    this.Key = CryptoJS.enc.Utf8.parse(this.func());
    this.iv = CryptoJS.enc.Utf8.parse(this.func());
    this.token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoiMCwnMzUxODg4JywwNzQ3OSIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCJ9.whOx0wZgxFwmeR__rkiG6PQF2fXkAwr2S2dUGxWL9sg";
    this.initializeWorker();
    this.loadPublicKey();
  }
  errorHandler(error) {
    let errorMessage = "";
    if (error.error instanceof ErrorEvent) {
      errorMessage = error.error.message;
    } else {
      let errorMsg = error.error.text;
      errorMessage = `Error Code: ${error.status}
Message: ${error.message}
 Error::${errorMsg}`;
    }
    this.httpoptionsfunc();
    return throwError(errorMessage);
  }
  getUserData() {
    let LoginVar = environment.productID.toString() + "LMSUserValues";
    return JSON.parse(this.decrypt(sessionStorage.getItem(LoginVar)));
  }
  httpoptionsfunc() {
    let currentUser1 = this.getUserData();
    this.httpOptions = {
      headers: new HttpHeaders({
        "Content-Type": "application/json; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policycontent": `default-src self'; font-src *;img-src * data:; script-src *; style-src *;`,
        "X-Frame-Options": "SAMEORIGIN",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        "Referrer-Policy": "no-referrer",
        "Access-Control-Allow-Methods": "GET,PUT,POST,DELETE",
        Authorization: `${currentUser1.token}`,
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Opener-Policy": "same-origin"
      })
    };
  }
  func() {
    let val = atob(environment.apiEndPoint.k);
    return val;
  }
  encrypt1(messageToencrypt) {
    if (messageToencrypt != "" && messageToencrypt != null && messageToencrypt != void 0) {
      let encryptedMessage = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(messageToencrypt), this.Key, {
        keySize: 128 / 8,
        iv: this.iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });
      return encryptedMessage.toString();
    }
    return null;
  }
  encrypt2(messageToencrypt, key) {
    let Key = CryptoJS.enc.Utf8.parse(atob(key));
    let iv = CryptoJS.enc.Utf8.parse(atob(key));
    if (messageToencrypt != "" && messageToencrypt != null && messageToencrypt != void 0) {
      let encryptedMessage = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(messageToencrypt), Key, {
        keySize: 128 / 8,
        iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });
      return encryptedMessage.toString();
    }
    return null;
  }
  decrypt(encryptedMessage) {
    if (encryptedMessage != "" && encryptedMessage != null && encryptedMessage != void 0) {
      let _enid = CryptoJS.AES.decrypt(encryptedMessage, this.Key, {
        keySize: 128 / 8,
        iv: this.iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }).toString(CryptoJS.enc.Utf8);
      return _enid;
    }
    return null;
  }
  encrypthttppost(messageToencrypt, key) {
    let key1 = CryptoJS.enc.Utf8.parse(key);
    let iv = CryptoJS.enc.Utf8.parse(key);
    if (messageToencrypt != "" && messageToencrypt != null && messageToencrypt != void 0) {
      let encryptedMessage = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(messageToencrypt), key1, {
        keySize: 128 / 8,
        iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });
      return encryptedMessage.toString();
    }
    return null;
  }
  decrypthttp(encryptedMessage, key) {
    let key1 = CryptoJS.enc.Utf8.parse(key);
    let iv = CryptoJS.enc.Utf8.parse(key);
    if (encryptedMessage != "" && encryptedMessage != null && encryptedMessage != void 0) {
      let _enid = CryptoJS.AES.decrypt(encryptedMessage, key1, {
        keySize: 128 / 8,
        iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      }).toString(CryptoJS.enc.Utf8);
      return _enid;
    }
    return null;
  }
  initializeWorker() {
    if (typeof Worker !== "undefined") {
      this.worker = new Worker(new URL("worker-UJ6F553W.js", import.meta.url), { type: "module" });
    }
  }
  loadPublicKey() {
    this.rsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoL5u4dVAH4ZEhiVCy0j2
7A9cqNnpmOqnLGGxS3mKdCHTbSXg1fSSQwxu/2tKTN9JGH0TYj1P10Gg7pGPRJHK
HXNiiyJ2GxLCucv6yvAi7vwt3uh2xLuZoxlGA//qSCaeEcTpJvaW16EXc90dV366
ARRdxW5XHhDd9jpXrZNuyqSUcEcYD4iZURC+HseBrrtP7FocON2ChXfZFtED1fTk
cXr3paqrlmJPxIcx8fx/BNLdfk6fdfrbkt+6Ke6arwGDupdnSGfSSFfSLAH9h2bL
jeGlnSdhViDYQkdA3tJx3IBquiuNsI15Dc1HyXV6/N/zLEJt9wFiw9ME5WdVrB81
CQIDAQAB
-----END PUBLIC KEY-----`;
  }
  encrypt(message) {
    return __async(this, null, function* () {
      if (!message)
        return null;
      return new Promise((resolve, reject) => {
        const handler = (event) => {
          this.worker.removeEventListener("message", handler);
          if (event.data.success) {
            resolve(event.data.result);
          } else {
            reject(new Error(event.data.error));
          }
        };
        this.worker.addEventListener("message", handler);
        this.worker.postMessage({
          action: "encrypt",
          plaintext: message,
          rsaPublicKey: this.rsaPublicKey
        });
      });
    });
  }
  decryptHybrid(encryptedPayload, iv) {
    return __async(this, null, function* () {
      if (!encryptedPayload || !iv)
        return null;
      return new Promise((resolve, reject) => {
        const handler = (event) => {
          this.worker.removeEventListener("message", handler);
          if (event.data.success) {
            resolve(event.data.result);
          } else {
            reject(new Error(event.data.error));
          }
        };
        this.worker.addEventListener("message", handler);
        this.worker.postMessage({
          action: "decryptResponse",
          data: encryptedPayload,
          iv
        });
      });
    });
  }
  destroyKey() {
    if (this.worker) {
      this.worker.postMessage({ action: "destroy" });
    }
  }
  ngOnDestroy() {
    if (this.worker) {
      this.worker.terminate();
    }
  }
  static {
    this.\u0275fac = function ShieldService_Factory(__ngFactoryType__) {
      return new (__ngFactoryType__ || _ShieldService)();
    };
  }
  static {
    this.\u0275prov = /* @__PURE__ */ \u0275\u0275defineInjectable({ token: _ShieldService, factory: _ShieldService.\u0275fac, providedIn: "root" });
  }
};
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(ShieldService, [{
    type: Injectable,
    args: [{
      providedIn: "root"
    }]
  }], () => [], null);
})();

export {
  ShieldService
};
