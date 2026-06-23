const fs = require('fs');

function rotDecrypt(str) {
    let res = "";
    for (let i = 0; i < str.length; i++) {
        res += String.fromCharCode(str.charCodeAt(i) - 1);
    }
    return res;
}

const base64 = "Li4uLi5DRkhKTyFTVEIhUVNKV0JVRiFMRlouLi4uLgtOSkpEWGhKQ0JCTENoSEZVZVZsWDJ4Ujp1UlVFdXljV3ViU2dCSmRQUWRaYjJESnM1TmdmW3pDSHJxcVRwbjBTCzNIOkdLazdZMUZvT1k0dXJ1V0dkTntoSXRxbkhLN05RbGVJYkRwQk5iT3ZtUkxiYzRnYlNxazBbTXkxejNIM2wLWktFVElvOnJbe1d7Q2xNeE44WXZibGNxcDB2M29FdFFpW3N7RmRsTnp6VUtMeHRVTmVleWtKOTJCaE5DQkJGRAtoWkJiZW15dWNTMjIzWkNrN1NwYntue3pnc2Q6SGJQOFJoczh2YnlRczUsOEg3aWM1eVVIbktUQlhKQ0NbZDh4C28yeWQ0MXtJMGdOMVlle1J3dktHTTBTWHhpNGxlNklYM3s5S0xEcFNYaXNJUmVvWVJPNEtrb1cyck9MTGw5aUULcTpRaW9bU1tTaXtYZzB5QzYwNDl2czZ6cjFlMm1vTUhWcXVQVDgwZjdaSmM1UktDQk1tbjdua017TlpDNzk0YgtZeXNPVlExVjI4aUljSVVRblhGNUZCaWJlNXZLcHY6Z2Nqb2p0Tk5IaUtsMmxuWld6WGtpUjVzck5WRHdtVklFC0M6YzIwTDFEUlJESERvcUxuNDJ7MFROTjYzSm94cHU6SEhoMU1icUd7bFN2Tkc4ZjRTckl0eDdqNHNOODNnWE0LMUt4SzpSZUNqMUZFdEg1bnZQc2N0e3ZaaDE3cDd2WHFCbEJlbE5jantXVnNabVZNTTg3cDJKTk56TjFbendKRwt0c0dnN3BRTkJVbDpJRmNMYjNxejhZN0pye3F0QkVwSVo1Uks1S3FZeWM4ejpOMVdncWU3ZVRJR0JsQ0JvTVtkC1dtMjAydHNbaHBQMEdNbDNoT2lqS3AxSmd6aWdWVVA3RUR6cHR3aWhNRGZNdTFJMXVwZHlEWnRKNGs2bXM6dDYLRlVSdDNXWW03NTMxUlM3W0JsQ1F3LEtZQ01iSFB6OVpSdGpTT1syVU5zW2xXSWpwTHBUTzh4UnM6SXE4e200SgtRMFBtW2hKNE9Oc3ZmQjR0WVtRVUUwZUVDRFR3WElmbkRuRXVZNkt2Cy4uLi4uRk9FIVNUQiFRU0pXQlVGIUxGWi4uLi4u";
const decoded = Buffer.from(base64, 'base64').toString('utf8');
const decrypted = rotDecrypt(decoded);

// Clean up formatting
const cleanKey = decrypted.replace(/-----BEGIN RSA PRIVATE KEY-----/, "")
                          .replace(/-----END RSA PRIVATE KEY-----/, "")
                          .replace(/\s/g, "");

const formattedKey = "-----BEGIN RSA PRIVATE KEY-----\n" + 
                     cleanKey.match(/.{1,64}/g).join("\n") + 
                     "\n-----END RSA PRIVATE KEY-----\n";

console.log(formattedKey);
