function DK() {
    var numericParts = [7348625, 9816254, 5271843];
    var jus = numericParts.map(function (num) {
        return String.fromCharCode(
            num % 256,
            Math.floor(num / 256) % 256,
            Math.floor(num / 65536) % 256
        );
    }).join("");
    var just = jus.padEnd(32, "0").substring(0, 32);
    return just;
}
function D_IV() {
    var ivNumericParts = [9816254, 5271843, 7348625];
    var ivString = ivNumericParts.map(function (num) {
        return String.fromCharCode(
            num % 256,
            Math.floor(num / 256) % 256,
            Math.floor(num / 65536) % 256
        );
    }).join("");
    ivString = ivString.padEnd(16, "0").substring(0, 16);
    return ivString;
}

function toHex(s) {
    var hex = "";
    for (var i = 0; i < s.length; i++) {
        hex += s.charCodeAt(i).toString(16).padStart(2, "0") + " ";
    }
    return hex.trim();
}

var key = DK();
var iv = D_IV();
console.log("Key: " + key + " (" + toHex(key) + ")");
console.log("IV:  " + iv + " (" + toHex(iv) + ")");