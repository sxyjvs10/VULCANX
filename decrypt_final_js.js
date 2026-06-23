const CryptoJS = require('crypto-js');

const privateClientEn = "sKGGn0MV4zwXrQR6WvZL9vQLrimVimMEdwiG/ddDnP+KV1/EHFjWlSLq11C7yrVwvVzKPXrp+VMQ5NomlkODN6Ln+l1AyF4Pr8T9I8sR+EJTIRrELsXuVCcVYJ+aVmuqvQDa7PrNG7I3pR6+fUJ3281FmIwThH/kts58VJSOBO/f8/Xpxk9BFeVPsqhwBBwwOigJONdwrZYswythxPwscXxYMfcuzip42EtxK8vlpUSAYUl129bhSbQIGK5tWkWEeo0GzSZAfTwUlbQtBK5sDkV5G8pY/a3yM+VtdQkf6K/rad9pLSWPs4xC+rjY3EmIivBZkdiBUIm+y64yLepNCNYs1uO6MO3EHqPWB+PPbcAaAp5jllfagM/+N19mEJ4LnTRqmgHUydPG7+hD5ER5xLhgwnfpn+0VKu7qvFNsPw2eeOssrsp9tBFHTRgPVT77GQ7nyDzCtoh4irSqBnfmgQ4b/VPDhbiFpU3rx6lWkaDOSP2NnT+j5PoHxJrXvDVIbs+yNQgFlugaCEjSkHChqeLDWfkqB3D8oZ4/ar6eZgyuHKUBAlDXhtdpNQ4t48PTdwlP3ah93jIuQxxyiD33K7OH+75P60QNdhGvL6OpSRQrwadJH8aMDq9v0dsT3BGHw4zzpnGgN/L4B7NNYWxi+pdMzj3QsjcFb40KwyhCstru0KGiXzMZRcYOw1NTpd4A57Mj7GdvBbxzIBwXCWL5IRl0ZIlRJr7hzo87Lim99/MgWxiL+K9OKPPKTtd7oOUUlTzabPujj6C/A87EF3VtJ9VUT8JRI7y1G4QBfe/pS64XY413ZXPjsISu6401JFu8w67dWulYwulWqkO35jWQphqiTPpgLWWGkLmykcP+sOkUBOU6s0iqvY7W57xlTpKKEVlV+DAZi35ZMiNT2XcZEsnA1IMzExHpEfY0ErDsQOGJcW/f3aGYmB3UdjQkqoH1xZKYXVoNh0oZsFynIQYi0+wchG2iSPYg3sBeQon4IwXSWyhUuNYxKHaymkg+Z/SxggnZ2x5gfFv5shSn3mmjN/2BAOfuWrv4KZs9b0u7ViRvSnZGu5k9tmvjzyVbfVU6FwHD9awkbwIzk8aL2zde0XYT+jGHjyrH9y7oMJC32NNZJxBwprfvVMdJxsCJPKkArY5k+3w5r0LkeP7VyVJyXrRn5B+wmvu3f7xNE195jAA=";

const bigPriEn = "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";

const k = Buffer.from("N3glRCpHLUthUGRTZ1YkQA==", 'base64').toString('utf8');
const k1 = Buffer.from("N3ghQSVEKkctS2FQZFNnVg==", 'base64').toString('utf8');

function do_decrypt(text, keyStr) {
    let Key = CryptoJS.enc.Utf8.parse(keyStr);
    let iv = CryptoJS.enc.Utf8.parse(keyStr);
    try {
        let dec = CryptoJS.AES.decrypt(text, Key, {
            keySize: 128 / 8,
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        return dec.toString(CryptoJS.enc.Utf8);
    } catch(e) { return null; }
}

console.log("privateClientEn (k): " + (do_decrypt(privateClientEn, k) ? "Success" : "Failed"));
console.log("privateClientEn (k1): " + (do_decrypt(privateClientEn, k1) ? "Success" : "Failed"));

console.log("bigPriEn (k): " + (do_decrypt(bigPriEn, k) ? "Success" : "Failed"));
console.log("bigPriEn (k1): " + (do_decrypt(bigPriEn, k1) ? "Success" : "Failed"));

// Let's print the decrypted bigPriEn if it's successful
let dec = do_decrypt(bigPriEn, k);
if (dec) console.log(dec.substring(0, 100) + "...");
let dec2 = do_decrypt(bigPriEn, k1);
if (dec2) console.log(dec2.substring(0, 100) + "...");
