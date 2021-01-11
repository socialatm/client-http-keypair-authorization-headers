var crypto = require('crypto');
var Hash = require('crypto').Hash;
// const { PrivateKeyObject, PublicKeyObject } = require('crypto')
exports.printMsg = function () {
    console.log('client-http-drf-keypair-permissions is loaded');
};
export var HttpMethod;
(function (HttpMethod) {
    HttpMethod["Get"] = "GET";
    HttpMethod["Post"] = "POST";
    HttpMethod["Put"] = "PUT";
    HttpMethod["Patch"] = "PATCH";
    HttpMethod["Update"] = "UPDATE";
    HttpMethod["Delete"] = "DELETE";
    HttpMethod["Options"] = "OPTIONS";
    HttpMethod["Head"] = "HEAD";
})(HttpMethod || (HttpMethod = {}));
/**
 * CavageHttpAuthorizer creates Cavage-compatible
 * HTTP authorization headers.
 * @class
 * @constructor
 * @public
 */
var HttpKeyPairAuthorizator = /** @class */ (function () {
    function HttpKeyPairAuthorizator() {
        this.modulusLength = 4096;
        this.publicKeyType = 'spki';
        this.privateKeyType = 'pkcs8';
        this.privateKeyFormat = 'pem';
        /* Access supported ciphers with `crypto.getCiphers()` */
        this.privateKeyCipher = 'aes-256-cbc';
        this.defaultPassphraseLength = 20;
        /**
         * Create a new CavageHttpAuthorizer
         */
        this.privateKeyPassphrase = this.generatePrivateKeyPassphrase();
    }
    Object.defineProperty(HttpKeyPairAuthorizator.prototype, "privateKeyPassphrase", {
        get: function () {
            /**
             * Retrieve the privateKeyPassphrase, used for generating new keypairs
             * @return {string} the instance's private key passphrase
             */
            return this.__privateKeyPassphrase;
        },
        set: function (passphrase) {
            /**
             * Set the instance's private key passphrase for generating new keypairs
             * @param {string} set the instance's passphrase. A null value will generate a random passphrase
             */
            if (passphrase) {
                this.__privateKeyPassphrase = this.generatePrivateKeyPassphrase(this.defaultPassphraseLength);
            }
            else {
                this.__privateKeyPassphrase = passphrase;
            }
        },
        enumerable: false,
        configurable: true
    });
    HttpKeyPairAuthorizator.prototype.generatePrivateKeyPassphrase = function (length) {
        if (length === void 0) { length = 20; }
        /**
         * Generate a new private key passphrase
         * @public
         * @param {length=} the character length of the passphrase
         * @return {string} a passphrase
         */
        if (length == undefined) {
            length = this.defaultPassphraseLength;
        }
        var result = '';
        var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
        var charactersLength = characters.length;
        for (var i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    };
    /*
    generateKeyPair (algorithm: string): KeyPair {
      /**
       * Generate a public key / private key keypair
       * @public
       * @param {string} an encription algorithm, such as 'rsa'. Must be 'rsa', 'dsa', 'ec', 'ed25519', 'ed448', 'x25519', 'x448', or 'dh'.
       *
      console.log(`cipher: ${this.privateKeyCipher}`);
      const keypair: KeyPair = crypto.generateKeyPairSync(algorithm, {
        modulusLength: this.modulusLength,
        publicKeyEncoding: {
          type: this.publicKeyType,
          format: 'der'
        },
        privateKeyEncoding: {
          type: this.privateKeyType,
          format: 'der',
          cipher: this.privateKeyCipher,
          passphrase: this.privateKeyPassphrase
        }
      });
      console.log(this.privateKeyPassphrase)
      console.log(keypair)
      return keypair
    }
    /* */
    HttpKeyPairAuthorizator.prototype.createMessageSignature = function (httpRequest, privateKey, hashAlgorithm, authorizationParameters, requiredAuthorizationHeaders) {
        /**
         * Create the message signature
         * @public
         */
        var httpHeaders = httpRequest.headers;
        var signingRows = [];
        if (requiredAuthorizationHeaders && requiredAuthorizationHeaders.length > 0) {
            for (var i = 0; i < requiredAuthorizationHeaders.length; i++) {
                var header = requiredAuthorizationHeaders[i];
                if (header[0] == '(') {
                    if (header == '(request-target)') {
                        var requestTarget = httpRequest.method.toLowerCase() + " " + httpRequest.path;
                        signingRows.push(header + ": " + requestTarget);
                    }
                    else {
                        var cleanedHeader = header.substr(1, header.length - 2);
                        signingRows.push(header + ": " + authorizationParameters[cleanedHeader]);
                    }
                }
                else {
                    var cleanedHeader = header.toLowerCase().split('-').map(function (word, index) {
                        return word.replace(word[0], word[0].toUpperCase());
                    }).join('-');
                    signingRows.push(header + ": " + httpHeaders[cleanedHeader]);
                }
            }
        }
        else {
            if (authorizationParameters.created) {
                signingRows.push("(created): " + authorizationParameters.created);
            }
            else if (httpHeaders.Date) {
                signingRows.push("date: " + httpHeaders.Date);
            }
            else {
                throw 'Date or created authorizationParameters required';
            }
        }
        var signingString = signingRows.join('\n');
        // return signingString
        /*
        const signature = crypto.sign(hashAlgorithm, Buffer.from(signingString), {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        }).toString('base64');
        /* */
        var signer = crypto.createSign(hashAlgorithm);
        signer.update(signingString);
        signer.end();
        var signature = signer.sign(privateKey, 'base64');
        return signature;
        /* */
    };
    HttpKeyPairAuthorizator.prototype.createAuthorizationHeader = function (httpRequest, privateKey, keyId, hashAlgorithm, authorizationParameters, requiredAuthorizationHeaders) {
        /**
         * Sign message. Algorithms are available at
         * @param {string} The public key to be used
         * @param {string} The algorithm to be used
         * @param {string[]} The header keys to be included in the authorization signature
         */
        var signature = this.createMessageSignature(httpRequest, privateKey, hashAlgorithm, authorizationParameters, requiredAuthorizationHeaders);
        var authorizationHeaderString = requiredAuthorizationHeaders.map(function (key, index) {
            return key;
        }).join(' ');
        var signatureHeaders = {
            algorithm: hashAlgorithm,
            keyId: keyId,
            signature: signature,
            headers: authorizationHeaderString
        };
        var signatureHeader = Object.keys(signatureHeaders).map(function (key, index) {
            var value = signatureHeaders[key];
            return key + "=\"" + value + "\"";
        }).join(',');
        /* */
        return signatureHeader;
    };
    HttpKeyPairAuthorizator.prototype.createDigestHeader = function (text, hashAlgorithm) {
        /**
         * Create a digest from a string. hashes are available at crypt.getHashes()
         * @param {string} The hashing algorithm to use, eg 'sha256' or 'sha512'
         * @param {string} The text to be digested
         */
        var digester = crypto.createHash(hashAlgorithm);
        var digest = digester.update(text).digest('base64');
        var header = hashAlgorithm + "=" + digest;
        return header;
    };
    return HttpKeyPairAuthorizator;
}());
export { HttpKeyPairAuthorizator };
// const auth = CavageHttpAuthorizer()
