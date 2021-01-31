"use strict";class HttpKeyPairAuthorizer{static get KEY_TYPE_PUBLIC(){return"public"}static get KEY_TYPE_PRIVATE(){return"private"}static createDigest(e,r){return new Promise((t=>{var i=new TextEncoder;window.crypto.subtle.digest(r,i.encode(e)).then((e=>{var r=window.btoa(String.fromCharCode.apply(null,new Uint8Array(e)));t(r)}))}))}static createDigestHeader(e,r){return new Promise((t=>{HttpKeyPairAuthorizer.createDigest(e,r).then((e=>{var i=`${r.toUpperCase().replace("-","")}=${e}`;t(i)}))}))}static createSigningMessage(e,r=null){var t=e.headers,i=[];if(r.headers&&r.headers.length>0)for(var a=r.headers,s=0;s<a.length;s++){var o=a[s];if("("===o[0])if("(request-target)"===o){var n=HttpKeyPairAuthorizer.getRequestTarget(e);i.push(`${o}: ${n}`)}else{var u=o.substring(1,o.length-1);i.push(`${o}: ${r[u]}`)}else{u=o.toLowerCase().split("-").map(((e,r)=>e.replace(e[0],e[0].toUpperCase()))).join("-");i.push(`${o}: ${t[u]}`)}}else{if(!t||!t.Date)throw Error('If no authorizationParameters.headers are specified, a "Date" HTTP header must exist to create');i.push(`date: ${t.Date}`)}return i.join("\n")}static createMessageSignature(e,r,t){var i=t.algorithm.toLowerCase(),a=null;0===i.indexOf("sha")?a="RSASSA-PKCS1-v1_5":0===i.indexOf("hmac")?a="HMAC":0===i.indexOf("ecdsa")&&((a={name:"ECDSA"}).hash=i.algorithm.substring("ECDSA".length).toUpperCase());var s=HttpKeyPairAuthorizer.createSigningMessage(e,t),o=new TextEncoder;return new Promise((e=>{window.crypto.subtle.sign(a,r,o.encode(s)).then((r=>{var t=window.btoa(String.fromCharCode.apply(null,new Uint8Array(r)));e(t)}))}))}static createAuthorizationHeader(e,r,t){return new Promise((i=>{HttpKeyPairAuthorizer.createMessageSignature(e,r,t).then((e=>{var r=e,a={},s="";if(t){for(var o in t)"headers"!==o&&"algorithmParameters"!==o&&(a[o]=t[o]);t.headers&&(s=t.headers.map(((e,r)=>e)).join(" "))}"SHA1"===t.algorithm?a.algorithm="RSA-SHA1":"SHA256"===t.algorithm?a.algorithm="RSA-SHA256":"SHA384"===t.algorithm?a.algorithm="RSA-SHA384":"SHA512"===t.algorithm&&(a.algorithm="RSA-SHA512"),a.signature=r,"Date"!==s&&(a.headers=s);var n=Object.keys(a).map(((e,r)=>{var t=a[e];return"string"==typeof t?`${e}="${t}"`:`${e}=${t}`})).join(",");i(`Signature ${n}`)}))}))}static digestHttpRequest(e,r){return new Promise((t=>{e.headers.Digest=HttpKeyPairAuthorizer.createDigestHeader(e.body,r),t(e)}))}static signHttpRequest(e,r,t,i=null){return i?new Promise((a=>{HttpKeyPairAuthorizer.createDigestHeader(e.body,i).then((i=>{e.headers.Digest=i,HttpKeyPairAuthorizer.signHttpRequestAfterDigest(e,r,t).then((r=>{a(e)}))}))})):HttpKeyPairAuthorizer.signHttpRequestAfterDigest(e,r,t)}static signHttpRequestAfterDigest(e,r,t){return new Promise((i=>{HttpKeyPairAuthorizer.createAuthorizationHeader(e,r,t).then((r=>{e.headers.Authorization=r,e.headers.Signature=r,i(e)}))}))}static getRequestTarget(e){return`${e.method.toLowerCase()} ${e.path}`}static arrayBufferToString(e){return String.fromCharCode.apply(null,new Uint8Array(e))}static stringToArrayBuffer(e){for(var r=new ArrayBuffer(e.length),t=new Uint8Array(r),i=0,a=e.length;i<a;i++)t[i]=e.charCodeAt(i);return r}static addNewLines(e,r){for(var t="";e.length>0;)t+=e.substring(0,r)+"\n",e=e.substring(r);return t}static doesDigestVerify(e,r){var t=r.indexOf("="),i=r.substring(0,t).toLowerCase(),a="";return"sha1"===i?a="SHA-1":"sha256"===i?a="SHA-256":"sha384"===i?a="SHA-384":"sha512"===i&&(a="SHA-512"),new Promise((t=>{HttpKeyPairAuthorizer.createDigestHeader(e,a).then((e=>{t(r===e)}))}))}static doesSignatureHeaderVerify(e,r,t){var i=HttpKeyPairAuthorizer.getAuthorizationParametersFromSignatureHeader(e),a=i.headers,s=Math.floor(Date.now()/1e3);if(a.includes("(created)")){if(!i.created)return!1;var o=parseInt(i.created);if(isNaN(o)||o>s)return!1}if(a.includes("(expires)")){if(!i.expires)return!1;var n=parseInt(i.expires);if(isNaN(n)||n<s)return!1}var u=null;if(0===i.algorithm.indexOf("RSA"))u="RSASSA-PKCS1-v1_5";else if(0===i.algorithm.indexOf("ECDSA")){u={name:"ECDSA"};var h=i.algorithm.split("-")[1];u.hash={name:h}}else 0===i.algorithm.indexOf("HMAC")&&(u="HMAC");var P=HttpKeyPairAuthorizer.createSigningMessage(r,i),g=new TextEncoder,p=HttpKeyPairAuthorizer.stringToArrayBuffer(window.atob(i.signature));return new Promise((e=>{window.crypto.subtle.verify(u,t,p,g.encode(P)).then((r=>{e(r)}))}))}static doesHttpRequestVerify(e,r){var t=e.headers.Authorization,i=e.headers.Signature,a=e.headers.Digest;return new Promise((s=>{var o="";t||i||s(!1),t&&i?(t!==i&&s(!1),o=t):t?o=t:i&&(o=i),a&&HttpKeyPairAuthorizer.doesDigestVerify(e.body,a).then((t=>{t||s(!1),HttpKeyPairAuthorizer.doesSignatureHeaderVerify(o,e,r).then((e=>{s(e)}))}))}))}static getAuthorizationParametersFromSignatureHeader(e){var r={};e.substring(e.indexOf(" ")+1).split(",").forEach(((e,t)=>{var i=e.indexOf("="),a=e.substring(0,i).trim(),s=e.substring(i+1).trim();if('"'===s[0])s=s.substring(1,s.length-1);else{var o=s.toLowerCase();if("true"===o)s=!0;else if("false"===o)s=!1;else{var n=parseFloat(s);isNaN(n)&&(s=n)}}r[a]=s})),r.headers||(r.headers="Date");var t=r.headers.split(" ");return r.headers=t,r}static exportPrivateKeyToPemString(e){return HttpKeyPairAuthorizer.exportKeyToPemString(HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE,e)}static exportPublicKeyToPemString(e){return HttpKeyPairAuthorizer.exportKeyToPemString(HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC,e)}static exportKeyToPemString(e,r){if(![HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC,HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE].includes(e))throw Error("Invalid key format. Must be HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC or HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE");var t="",i="";return e===HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC?(t="PUBLIC",i="spki"):(t="PRIVATE",i="pkcs8"),new Promise((e=>{window.crypto.subtle.exportKey(i,r).then((r=>{var i=r,a=HttpKeyPairAuthorizer.arrayBufferToString(i),s=window.btoa(a),o=HttpKeyPairAuthorizer.addNewLines(s,64);e(`-----BEGIN ${t} KEY-----\n${o}-----END ${t} KEY-----`)}))}))}static importPrivateKeyFromPemString(e,r){return HttpKeyPairAuthorizer.importKeyFromPemString(HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE,e,r)}static importPublicKeyFromPemString(e,r){return HttpKeyPairAuthorizer.importKeyFromPemString(HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC,e,r)}static importKeyFromPemString(e,r,t){if(![HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC,HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE].includes(e))throw Error("Invalid key format. Must be HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC or HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE");var i=[],a="";e===HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC?(i.push("verify"),a="spki"):(i.push("sign"),a="pkcs8");var s=r.replace(/-{5}(BEGIN|END)([A-Z ]*)KEY-{5}?/g,""),o=window.atob(s),n=HttpKeyPairAuthorizer.stringToArrayBuffer(o);return new Promise(((e,r)=>{window.crypto.subtle.importKey(a,n,t,!0,i).then((r=>{e(r)})).catch((()=>{throw Error("Error processing your PEM string into a CryptoKey. Your PEM format is likely incompatible. Make sure it PKCS #8 or SPKI compatible")}))}))}}
