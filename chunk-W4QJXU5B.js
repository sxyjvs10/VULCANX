import {
  require_crypto_js
} from "./chunk-U4FAYTJH.js";
import {
  SessionTimeoutService
} from "./chunk-C42OSM34.js";
import {
  Router
} from "./chunk-L2TX3H2Y.js";
import {
  environment
} from "./chunk-L5HWXGQY.js";
import {
  HttpClient,
  HttpHeaders,
  Injectable,
  __toESM,
  catchError,
  map,
  setClassMetadata,
  ɵɵdefineInjectable,
  ɵɵinject
} from "./chunk-DMFUQV5T.js";

// src/app/pages/login/authentication.service.ts
var CryptoJS = __toESM(require_crypto_js());
var AuthenticationService = class _AuthenticationService {
  constructor(http, router, sessiontimeoutService) {
    this.http = http;
    this.router = router;
    this.sessiontimeoutService = sessiontimeoutService;
  }
  login(postData) {
    const headers = new HttpHeaders().set("Content-Type", "application/json; charset=utf-8");
    let loginUrl = !postData["isGoldEmployee"] ? environment.apiEndPoint.loginLMS : environment.apiEndPoint.loginMafil;
    return this.http.post(loginUrl, postData, { headers }).pipe(map((user) => {
      if (user && user.token && !postData["isGoldEmployee"]) {
        user["branchID"] = postData["BranchID"];
        user["branchName"] = postData["BranchName"];
        user["isMafilEmployee"] = 0;
        localStorage.setItem(environment.localStorageItem, JSON.stringify(user));
        localStorage.setItem("accessToken", user.token.access_token);
        localStorage.setItem("refreshToken", user.token.refresh_token);
      }
      return user;
    }));
  }
  ssologin(postData) {
    const headers = new HttpHeaders().set("Content-Type", "application/json; charset=utf-8");
    let loginUrl = !postData["isGoldEmployee"] ? environment.apiEndPoint.ssologinLOS : environment.apiEndPoint.loginMafil;
    return this.http.post(loginUrl, postData, { headers }).pipe(map((user) => {
      if (user) {
        localStorage.setItem(environment.localStorageItem, JSON.stringify(user));
        localStorage.setItem("accessToken", user.accessToken.Token.access_token);
        localStorage.setItem("refreshToken", user.accessToken.Token.refresh_token);
        this.startRefreshTokenTimer();
      }
      return user;
    }));
  }
  clearSession(postData) {
    const headers = new HttpHeaders().set("Content-Type", "application/json; charset=utf-8");
    let loginUrl = environment.apiEndPoint.sessionClear;
    return this.http.post(loginUrl, postData, { headers }).pipe(map((user) => {
      return user;
    }));
  }
  roleList() {
    const headers = new HttpHeaders().set("Content-Type", "application/json; charset=utf-8");
    const roleUrl = environment.apiEndPoint.getRolelist;
    return this.http.get(roleUrl, { headers });
  }
  startRefreshTokenTimer() {
    const timeout = 4 * 60 * 1e3;
    this.refreshTokenTimeout = setTimeout(() => {
      this.callRefreshTokenAPI();
    }, timeout);
  }
  callRefreshTokenAPI() {
    const RefreshToken = localStorage.getItem("refreshToken");
    if (!RefreshToken || RefreshToken === "undefined" || RefreshToken === "null") {
      console.warn("Missing or invalid refresh token");
      this.logout();
      return;
    }
    const headers = new HttpHeaders().set("Content-Type", "application/json; charset=utf-8");
    const refreshData = { RefreshToken };
    const refreshUrl = environment.apiEndPoint?.tokenRefresh;
    if (!refreshUrl) {
      console.error("Refresh URL not defined");
      this.logout();
      return;
    }
    this.http.post(refreshUrl, refreshData, { headers }).pipe(map((response) => {
      if (response?.AcessToken) {
        localStorage.setItem("accessToken", response.AcessToken);
        const userDataRaw = localStorage.getItem(environment.localStorageItem);
        if (userDataRaw) {
          try {
            const userData = JSON.parse(userDataRaw);
            if (userData.token) {
              userData.token.access_token = response.AcessToken;
              localStorage.setItem(environment.localStorageItem, JSON.stringify(response));
              localStorage.setItem(environment.localStorageItem, JSON.stringify(userData));
            }
          } catch (error) {
            console.error("Error parsing user data:", error);
          }
        }
        this.startRefreshTokenTimer();
        return response;
      } else {
        console.warn("Invalid refresh response");
        this.logout();
        return null;
      }
    }), catchError((err) => {
      console.error("Token refresh failed:", err);
      if (err.status === 401) {
        this.router.navigate(["/pages/errors/not-found"]);
      }
      throw err;
    })).subscribe({
      next: (response) => {
        if (response) {
          console.log("Token refreshed successfully");
        }
      },
      error: (err) => {
        console.error("Final token refresh error:", err);
      }
    });
  }
  loginMicrofinance(postData) {
    const headers = new HttpHeaders().set("Content-Type", "application/json; charset=utf-8");
    let loginUrl = environment.apiEndPoint.mafilCustomerApi;
    return this.http.post(loginUrl, postData, { headers });
  }
  loginCheck(postData) {
    const headers = new HttpHeaders().set("Content-Type", "application/json; charset=utf-8");
    let loginUrl = environment.apiEndPoint.loginLMS;
    return this.http.post(loginUrl, postData, { headers }).pipe(map((user) => {
      return user;
    }));
  }
  logout(reason) {
    console.warn("Logging out due to:", reason || "manual trigger");
    clearTimeout(this.refreshTokenTimeout);
    localStorage.removeItem(environment.localStorageItem);
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
    localStorage.removeItem("isEsign");
    localStorage.removeItem("customerToken");
    this.sessiontimeoutService.stop();
  }
  decodeJWT(token) {
    try {
      const payload = token.split(".")[1];
      return JSON.parse(atob(payload));
    } catch (e) {
      return null;
    }
  }
  getProductList() {
    const body = {
      flag: "1",
      FirmID: "1"
    };
    return this.http.post(environment.apiEndPoint.products, body);
  }
  getBranchList(params) {
    return this.http.post(environment.apiEndPoint.getBranchList, params);
  }
  getGoldServiceBranchList(params) {
    return this.http.post(environment.apiEndPoint.getEmployee, params);
  }
  changePassword(params) {
    return this.http.post(environment.apiEndPoint.changePassword, params);
  }
  forgotpassword(params) {
    return this.http.post(environment.apiEndPoint.forgotPassword, params);
  }
  verifyOTP(params) {
    return this.http.post(environment.apiEndPoint.verifyOTP, params);
  }
  resetPassword(params) {
    return this.http.post(environment.apiEndPoint.resetPassword, params);
  }
  setPassword(keys, value) {
    var key = CryptoJS.enc.Utf8.parse(keys);
    var iv = CryptoJS.enc.Utf8.parse(keys);
    var encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(value.toString()), key, { keySize: 128 / 8, mode: CryptoJS.mode.ECB });
    return encrypted.toString();
  }
  getPassword(keys, value) {
    var key = CryptoJS.enc.Utf8.parse(keys);
    var iv = CryptoJS.enc.Utf8.parse(keys);
    var decrypted = CryptoJS.AES.decrypt(value, key, {
      keySize: 128 / 8,
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
  }
  static {
    this.\u0275fac = function AuthenticationService_Factory(__ngFactoryType__) {
      return new (__ngFactoryType__ || _AuthenticationService)(\u0275\u0275inject(HttpClient), \u0275\u0275inject(Router), \u0275\u0275inject(SessionTimeoutService));
    };
  }
  static {
    this.\u0275prov = /* @__PURE__ */ \u0275\u0275defineInjectable({ token: _AuthenticationService, factory: _AuthenticationService.\u0275fac });
  }
};
(() => {
  (typeof ngDevMode === "undefined" || ngDevMode) && setClassMetadata(AuthenticationService, [{
    type: Injectable
  }], () => [{ type: HttpClient }, { type: Router }, { type: SessionTimeoutService }], null);
})();

export {
  AuthenticationService
};
