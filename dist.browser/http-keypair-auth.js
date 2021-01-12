var crypto = require('crypto');
var Hash = require('crypto').Hash;
var Sign = require('crypto').Sign;
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
 *
 * @class
 * @constructor
 * @public
 */
var HttpKeyPairAuthorizer = /** @class */ (function () {
    function HttpKeyPairAuthorizer() {
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
    Object.defineProperty(HttpKeyPairAuthorizer.prototype, "privateKeyPassphrase", {
        get: function () {
            /**
             * Retrieve the privateKeyPassphrase, used for generating new keypairs
             *
             * @return {string} the instance's private key passphrase
             */
            return this.__privateKeyPassphrase;
        },
        set: function (passphrase) {
            /**
             * Set the instance's private key passphrase for generating new keypairs
             *
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
    HttpKeyPairAuthorizer.prototype.generatePrivateKeyPassphrase = function (length) {
        if (length === void 0) { length = 20; }
        /**
         * Generate a new private key passphrase
         *
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
    HttpKeyPairAuthorizer.prototype.createSigningMessage = function (httpRequest, authorizationParameters, requiredAuthorizationHeaders) {
        /**
         * Create the string that will be signed, from the HTTP headers.
         *
         * @public
         * @param {HttpRequest} The HTTP Request information including the headers
         * @param {Record<string, any>} the extra Authorization string parameters which will be included, such as `created` or `expires` timestamps
         * @param {string[]} An ordered list of headers to use to bulid the signing message
         * @return {string} the signing message
         */
        var httpHeaders = httpRequest.headers;
        var signingRows = [];
        if (requiredAuthorizationHeaders && requiredAuthorizationHeaders.length > 0) {
            for (var i = 0; i < requiredAuthorizationHeaders.length; i++) {
                var header = requiredAuthorizationHeaders[i];
                if (header[0] === '(') {
                    if (header === '(request-target)') {
                        var requestTarget = this.__getRequestTarget(httpRequest);
                        signingRows.push(header + ": " + requestTarget);
                    }
                    else {
                        var cleanedHeader = header.substring(1, header.length - 1);
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
            if (httpHeaders && httpHeaders.Date) {
                signingRows.push("date: " + httpHeaders.Date);
            }
            else {
                throw Error('If no requiredAuthorizationHeaders are specified, a "Date" HTTP header must exist to create');
            }
        }
        var signingMessage = signingRows.join('\n');
        return signingMessage;
    };
    HttpKeyPairAuthorizer.prototype.createMessageSignature = function (httpRequest, privateKey, hashAlgorithm, authorizationParameters, requiredAuthorizationHeaders) {
        /**
         * Create the message signature
         *
         * @private
         * @param {HttpRequest} An object containing information about HTTP request headers, method, and body.
         * @param {crypto.PrivateKeyObject} The private key used to create the signature
         * @param {string} the hashing algorithm. Get a list of supported hashing algorithms from crypto.getHashes()
         * @param {Record<string: string>} A dictionary of headers and pseudo-headers which will be used to build the message to be signed
         * @param {string[]} A list of headers and pseudo-headers to be used to build the signed message
         * @return {string} A signature created from the parameters provided
         */
        var signingMessage = this.createSigningMessage(httpRequest, authorizationParameters, requiredAuthorizationHeaders);
        var signer = crypto.createSign(hashAlgorithm);
        signer.update(signingMessage);
        signer.end();
        var signature = signer.sign(privateKey, 'base64');
        return signature;
    };
    HttpKeyPairAuthorizer.prototype.createAuthorizationHeader = function (httpRequest, privateKey, keyId, hashAlgorithm, authorizationParameters, requiredAuthorizationHeaders) {
        /**
         * Sign message. Algorithms are available at
         *
         * @public
         * @param {string} The public key to be used
         * @param {string} The algorithm to be used
         * @param {string[]} The header keys to be included in the authorization signature
         * @return {string} The full Authorization HTTP header including algorithm="", keyId="", signature="", and headers="".
         */
        var signature = this.createMessageSignature(httpRequest, privateKey, hashAlgorithm, authorizationParameters, requiredAuthorizationHeaders);
        var signatureHeaders = {
            algorithm: hashAlgorithm,
            keyId: keyId,
            signature: signature
        };
        for (var key in authorizationParameters) {
            signatureHeaders[key] = authorizationParameters[key];
        }
        var authorizationHeaderString = requiredAuthorizationHeaders.map(function (key, index) {
            return key;
        }).join(' ');
        // we can omit the headers="" if it's only Date
        if (authorizationHeaderString !== 'Date') {
            signatureHeaders.headers = authorizationHeaderString;
        }
        var signatureHeader = Object.keys(signatureHeaders).map(function (key, index) {
            var value = signatureHeaders[key];
            var output = '';
            if (typeof value == 'string') {
                output = key + "=\"" + value + "\"";
            }
            else {
                output = key + "=" + value;
            }
            return output;
        }).join(',');
        /* */
        var header = "Signature " + signatureHeader;
        return header;
    };
    HttpKeyPairAuthorizer.prototype.createDigestHeader = function (text, hashAlgorithm) {
        /**
         * Create a digest from a string. hashes are available at crypt.getHashes()
         *
         * @public
         * @param {string} The hashing algorithm to use, eg 'sha256' or 'sha512'
         * @param {string} The text to be digested
         * @return {string} A hash digest of the text variable
         */
        var digester = crypto.createHash(hashAlgorithm);
        var digest = digester.update(text).digest('base64');
        var header = hashAlgorithm + "=" + digest;
        return header;
    };
    HttpKeyPairAuthorizer.prototype.doesDigestVerify = function (text, digest) {
        /**
         * Verify the digest header.
         *
         * @public
         * @param {string} The http message body
         * @param {string} The digest header, which includes the hash in the digest string.
         * @param {boolean} `true` if digest verifies, `false` otherwise
         */
        var splitPoint = digest.indexOf('=');
        var hashAlgorithm = digest.substring(0, splitPoint);
        var base64DigestString = digest.substring(splitPoint + 1);
        var expectedDigestHeader = this.createDigestHeader(text, hashAlgorithm);
        var doesVerify = (digest == expectedDigestHeader);
        return doesVerify;
    };
    HttpKeyPairAuthorizer.prototype.doesSignatureHeaderVerify = function (header, httpRequest, publicKey) {
        /**
         * Verifies a HTTP keypair authorization signature against a locally stored public key
         *
         * @public
         * @param {string} The signature to verify
         * @param {HttpRequest} The HTTP request information including a body, headers, and more.
         * @param {crypto.PublicKeyObject} A public key to verify the signature
         * @return {boolean} `true` if signature verifies, `false` otherwise
         */
        // const requestTarget: string = this.__getRequestTarget(httpRequest);
        var authorizationParameters = this.getAuthorizationParametersFromSignatureHeader(header);
        var requiredAuthorizationHeaders = authorizationParameters.headers;
        var currentTimestamp = Math.floor(Date.now() / 1000) - (60 * 60 * 24);
        // if an authorizationParameters.created exists, make sure it's not in the future
        if (requiredAuthorizationHeaders.includes('(created)')) {
            if (!authorizationParameters.created) {
                return false;
            }
            else {
                var created = parseInt(authorizationParameters.created);
                if (created == NaN || created > currentTimestamp) {
                    return false;
                }
            }
        }
        // if an authorizationParameters.expires exists, make sure it's not in the past
        if (requiredAuthorizationHeaders.includes('(expires)')) {
            if (!authorizationParameters.created) {
                return false;
            }
            else {
                var expires = parseInt(authorizationParameters.expires);
                if (expires == NaN || expires < currentTimestamp) {
                    return false;
                }
            }
        }
        var signingMessage = this.createSigningMessage(httpRequest, authorizationParameters, requiredAuthorizationHeaders);
        var doesVerify = crypto.verify(authorizationParameters.algorithm, Buffer.from(signingMessage), {
            key: publicKey,
        }, Buffer.from(authorizationParameters.signature, 'base64'));
        return doesVerify;
    };
    HttpKeyPairAuthorizer.prototype.doesHttpRequestVerify = function (httpRequest, publicKey) {
        /**
         * Verify an entire HttpRequest.  There should be identical `Authorization` and `Signature` headers
         *
         * @public
         * @param {HttpRequest} The HTTP request information including a body, headers, and more.
         * @param {crypto.PublicKeyObject} A public key to verify the signature
         * @return {boolean} `true` if HttpRequest verifies, `false` otherwise
         */
        var authorizationHeader = httpRequest.headers['Authorization'];
        var signatureHeader = httpRequest.headers['Signature'];
        var digestHeader = httpRequest.headers['Digest'];
        if (!authorizationHeader) {
            return false;
        }
        if (!signatureHeader) {
            return false;
        }
        if (authorizationHeader != signatureHeader) {
            return false;
        }
        if (digestHeader) {
            var doesDigestVerify = this.doesDigestVerify(httpRequest.body, digestHeader);
            if (!doesDigestVerify) {
                return false;
            }
        }
        return this.doesSignatureHeaderVerify(authorizationHeader, httpRequest, publicKey);
    };
    HttpKeyPairAuthorizer.prototype.getAuthorizationParametersFromSignatureHeader = function (signatureHeader) {
        /**
         * Convert a raw signature header to its component data
         *
         * @public method
         * @param {string} The HTTP signature header
         * @return {Record<string,any>} A dictionary of key/value pairs
         */
        var authorizationParameters = {};
        var signatureDataString = signatureHeader.substring(signatureHeader.indexOf(' ') + 1);
        var signatureData = signatureDataString.split(',');
        signatureData.forEach(function (item, index) {
            var splitPoint = item.indexOf('=');
            var key = item.substring(0, splitPoint).trim();
            var value = item.substring(splitPoint + 1).trim();
            if (value[0] === '"') {
                value = value.substring(1, value.length - 1);
            }
            else {
                var lowercaseValue = value.toLowerCase();
                if (lowercaseValue == 'true') {
                    value = true;
                }
                else if (lowercaseValue == 'false') {
                    value = false;
                }
                else {
                    var numericValue = parseFloat(value);
                    if (numericValue != NaN) {
                        value = numericValue;
                    }
                }
            }
            authorizationParameters[key] = value;
        });
        // if no headers are specified, the default is to find a HTTP Date header
        if (!authorizationParameters.headers) {
            authorizationParameters.headers = 'Date';
        }
        var requiredAuthorizationHeaders = authorizationParameters.headers.split(' ');
        authorizationParameters.headers = requiredAuthorizationHeaders;
        return authorizationParameters;
        /* */
    };
    HttpKeyPairAuthorizer.prototype.__getRequestTarget = function (httpRequest) {
        /**
         * Build an authorization-compatible (request-target) string, such as 'post /path/to/endpoint?query=param'
         *
         * @private
         * @param {HttpRequest} The HTTP request to process
         * @return {string} The authorization-compatible (request-target) string.
         */
        return httpRequest.method.toLowerCase() + " " + httpRequest.path;
    };
    return HttpKeyPairAuthorizer;
}());
export default HttpKeyPairAuthorizer;
// const auth = CavageHttpAuthorizer()
