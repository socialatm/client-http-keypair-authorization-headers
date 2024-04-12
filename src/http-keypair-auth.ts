const crypto = require('crypto');
const { Hash } = require('crypto');
const { Sign } = require('crypto');


exports.printMsg = function () {
  console.log('client-http-keypair-authorization is loaded')
}

if (typeof btoa === 'undefined') {
  global.btoa = function (str) {
    return new Buffer(str, 'binary').toString('base64');
  };
}

if (typeof atob === 'undefined') {
  global.atob = function (b64Encoded) {
    return new Buffer(b64Encoded, 'base64').toString('binary');
  };
}

export interface HttpHeaders {
  [key: string]: string;
}

export enum HttpMethod {
  Get = "GET",
  Post = "POST",
  Put = "PUT",
  Patch = "PATCH",
  Update = "UPDATE",
  Delete = "DELETE",
  Options = "OPTIONS",
  Head = "HEAD"
}

export interface HttpRequest {
  method: HttpMethod;
  path: string;
  headers: HttpHeaders;
  body: string;
}

/**
 * CavageHttpAuthorizer creates Cavage-compatible
 * HTTP authorization headers.
 *
 * @class
 * @constructor
 * @public
 */
export default class HttpKeyPairAuthorizer {

  static createSigningMessage(httpRequest: HttpRequest, authorizationParameters?: Record<string,any>): string {
    /**
     * Create the string that will be signed, from the HTTP headers.
     *
     * @public
     * @param {HttpRequest} The HTTP Request information including the headers
     * @param {Record<string, any>} the extra Authorization string parameters which will be included, such as `created` or `expires` timestamps
     * @param {string[]} An ordered list of headers to use to bulid the signing message
     * @return {string} the signing message
     */
    const httpHeaders: Record<string, any> = httpRequest.headers;
    const signingRows: string[] = [];
    if (authorizationParameters.headers && authorizationParameters.headers.length > 0) {
      const requiredAuthorizationHeaders: string[] = authorizationParameters.headers;
      for (let i=0; i<requiredAuthorizationHeaders.length; i++) {
        const header: string = requiredAuthorizationHeaders[i];
        if (header[0] === '(') {
          if (header === '(request-target)') {
            const requestTarget: string = HttpKeyPairAuthorizer.__getRequestTarget(httpRequest);
            signingRows.push(`${header}: ${requestTarget}`)
          } else {
            const cleanedHeader: string = header.substring(1, header.length - 1)
            signingRows.push(`${header}: ${authorizationParameters[cleanedHeader]}`)
          }
        } else {
          const cleanedHeader: string = header.toLowerCase().split('-').map( (word: string, index: number) => {
            return word.replace(word[0], word[0].toUpperCase());
          }).join('-');
          signingRows.push(`${header}: ${httpHeaders[cleanedHeader]}`);
        }
      }
    } else {
     if (httpHeaders && httpHeaders.Date) {
       signingRows.push(`date: ${httpHeaders.Date}`);
     } else {
       throw Error('If no authorizationParameters.headers are specified, a "Date" HTTP header must exist to create')
     }
    }
    const signingMessage: string = signingRows.join('\n');
    return signingMessage
  }

  static createMessageSignature (httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string,any>): string {
    /**
     * Create the message signature
     *
     * @private
     * @param {HttpRequest} An object containing information about HTTP request headers, method, and body.
     * @param {crypto.PrivateKeyObject} The private key used to create the signature
     * @param {string} the hashing algorithm. Get a list of supported hashing algorithms from crypto.getHashes()
     * @param {Record<string: string>} A dictionary of headers and pseudo-headers which will be used to build the message to be signed
     * @return {string} A signature created from the parameters provided
     */
    const signingMessage: string = HttpKeyPairAuthorizer.createSigningMessage(httpRequest, authorizationParameters);
    const signer: typeof crypto.Sign = crypto.createSign(authorizationParameters.algorithm);
    signer.update(signingMessage);
    signer.end();
    const signature: string = signer.sign(privateKey, 'base64');
    return signature;
  }

  static createAuthorizationHeader (httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string,any>): string {
    /**
     * Sign message. Algorithms are available at
     *
     * @public
     * @param {string} The public key to be used
     * @param {string} The algorithm to be used
     * @param {string[]} The header keys to be included in the authorization signature
     * @return {string} The full Authorization HTTP header including algorithm="", keyId="", signature="", and headers="".
     */
    const signature: string = HttpKeyPairAuthorizer.createMessageSignature(httpRequest, privateKey, authorizationParameters);
    const signatureHeaders: Record<string,any> = {};
    let authorizationHeaderString: string = '';
    if (authorizationParameters) {
      for (const key in authorizationParameters) {
        if (key != 'headers') {
          signatureHeaders[key] = authorizationParameters[key];
        }
      }
      if (authorizationParameters.headers) {
        authorizationHeaderString = authorizationParameters.headers.map((key: string, index: number) => {
          return key;
        }).join(' ');
      }
    }
    if (authorizationParameters.algorithm === 'SHA-1') {
      signatureHeaders.algorithm = 'RSA-SHA1'
    } else if (authorizationParameters.algorithm === 'SHA-256') {
      signatureHeaders.algorithm = 'RSA-SHA256'
    } else if (authorizationParameters.algorithm === 'SHA-384') {
      signatureHeaders.algorithm = 'RSA-SHA384'
    } else if (authorizationParameters.algorithm === 'SHA-512') {
      signatureHeaders.algorithm = 'RSA-SHA512'
    }
    signatureHeaders.signature = signature
    // we can omit the headers="" if it's only Date
    if (authorizationHeaderString !== 'Date') {
      signatureHeaders.headers = authorizationHeaderString;
    }
    const signatureHeader: string = Object.keys(signatureHeaders).map( (key: string, index: number) => {
      const value: any = signatureHeaders[key];
      let output: string = '';
      if (typeof value == 'string') {
        output = `${key}="${value}"`;
      } else {
        output = `${key}=${value}`;
      }
      return output;
    }).join(',');
    /* */
    const header: string = `Signature ${signatureHeader}`;
    return header;
  }

  static createDigestHeader (text: string, hashAlgorithm: string): string {
    /**
     * Create a digest from a string. hashes are available at crypt.getHashes()
     *
     * @public
     * @param {string} The hashing algorithm to use, eg 'sha256' or 'sha512'
     * @param {string} The text to be digested
     * @return {string} A hash digest of the text variable
     */
    const digester: typeof Hash = crypto.createHash(hashAlgorithm);
    const digest: string = digester.update(text).digest('base64');
    const header: string = `${hashAlgorithm}=${digest}`;
    return header;
  }

  static digestHttpRequest(httpRequest: HttpRequest, hashAlgorithm: string) {
    /**
     * Create a digest header on a httpRequest
     *
     * @param {HttpRequest} The HTTP Request including a `.body` and `.headers`
     * @param {string} the hash algorithm. Get supported algorithmsfrom `crypto.getHashes()`
     * @return {HttpRequest} An updated dictionary with a `Digest` header
     */
     httpRequest.headers['Digest'] = HttpKeyPairAuthorizer.createDigestHeader(httpRequest.body, hashAlgorithm);
     return httpRequest;
  }

  static signHttpRequest(httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string,any>, digestHashAlgorithm?: string): HttpRequest {
    /**
     * Create a signed authorization header (and possibly a digest) and place it in the HttpRequest.
     *
     * @param {HttpRequest} The HTTP Request including a `.body` and `.headers`
     * @param {crypto.PrivateKeyObject} The private key which will sign the request
     * @param {string} The key ID as it's known on the server of the signing key's public key
     * @param {string} The algorithm used to sign the message. Get supported algorithms from `crypto.getHashes()`
     * @param {Record<string,any>} The parameters used to generate the signature header
     * @param {string?} The hash algorithm used to create a digest header, if desired (optional, required if `digest` in 'requiredParameters.headers')
     * @return {HttpRequest} The updated dictionary with `Authorization` and `Signature` headers, and possibly a `Digest` header
     */
    if (digestHashAlgorithm) {
      httpRequest.headers['Digest'] = HttpKeyPairAuthorizer.createDigestHeader(httpRequest.body, digestHashAlgorithm);
    }
    const authorizationHeader: string = HttpKeyPairAuthorizer.createAuthorizationHeader(httpRequest, privateKey, authorizationParameters);
    httpRequest.headers['Authorization'] = authorizationHeader;
    httpRequest.headers['Signature'] = authorizationHeader;
    return httpRequest;
  }

  static doesDigestVerify (text: string, digest: string): boolean {
    /**
     * Verify the digest header.
     *
     * @public
     * @param {string} The http message body
     * @param {string} The digest header, which includes the hash in the digest string.
     * @param {boolean} `true` if digest verifies, `false` otherwise
     */
    const splitPoint: number = digest.indexOf('=');
    const hashAlgorithm: string = digest.substring(0, splitPoint);
    const base64DigestString: string = digest.substring(splitPoint + 1)
    const expectedDigestHeader: string = HttpKeyPairAuthorizer.createDigestHeader(text, hashAlgorithm)
    const doesVerify: boolean = (digest == expectedDigestHeader);
    return doesVerify;
  }

  static doesSignatureHeaderVerify (header: string, httpRequest: HttpRequest, publicKey: typeof crypto.PublicKeyObject): boolean {
    /**
     * Verifies a HTTP keypair authorization signature against a locally stored public key
     *
     * @public
     * @param {string} The signature to verify
     * @param {HttpRequest} The HTTP request information including a body, headers, and more.
     * @param {crypto.PublicKeyObject} A public key to verify the signature
     * @return {boolean} `true` if signature verifies, `false` otherwise
     */
     // const requestTarget: string = HttpKeyPairAuthorizer.__getRequestTarget(httpRequest);
     const authorizationParameters: Record<string,any> = HttpKeyPairAuthorizer.getAuthorizationParametersFromSignatureHeader(header);
     const requiredAuthorizationHeaders: string[] = authorizationParameters.headers;
     const currentTimestamp: number = Math.floor(Date.now() / 1000);
     // if an authorizationParameters.created exists, make sure it's not in the future
     if (requiredAuthorizationHeaders.includes('(created)')) {
       if (!authorizationParameters.created) {
         return false;
       } else {
         const created: number = parseInt(authorizationParameters.created)
         if (isNaN(created) || created > currentTimestamp) {
           return false;
         }
       }
     }
     // if an authorizationParameters.expires exists, make sure it's not in the past
     if (requiredAuthorizationHeaders.includes('(expires)')) {
       if (!authorizationParameters.expires) {
         return false;
       } else {
         const expires: number = parseInt(authorizationParameters.expires)
         if (isNaN(expires) || expires < currentTimestamp) {
           return false;
         }
       }
     }
     const signingMessage: string = HttpKeyPairAuthorizer.createSigningMessage(httpRequest, authorizationParameters);
     const doesVerify: boolean = crypto.verify(
       authorizationParameters.algorithm,
       Buffer.from(signingMessage),
       {
         key: publicKey,
       },
       Buffer.from(authorizationParameters.signature, 'base64')
     );
     return doesVerify;
  }

  static doesHttpRequestVerify (httpRequest: HttpRequest, publicKey: typeof crypto.PublicKeyObject): boolean {
    /**
     * Verify an entire HttpRequest.  There should be identical `Authorization` and `Signature` headers
     *
     * @public
     * @param {HttpRequest} The HTTP request information including a body, headers, and more.
     * @param {crypto.PublicKeyObject} A public key to verify the signature
     * @return {boolean} `true` if HttpRequest verifies, `false` otherwise
     */
    const authorizationHeader: string = httpRequest.headers['Authorization'];
    const signatureHeader: string = httpRequest.headers['Signature'];
    const digestHeader: string = httpRequest.headers['Digest'];
    // There may be either an Authorization or a Signature
    if (!authorizationHeader && !signatureHeader) {
      return false;
    }
    let header;
    // if there are both an Authorization and Signature, they should match
    if (authorizationHeader && signatureHeader) {
      if (authorizationHeader != signatureHeader) {
        return false;
      }
      header = authorizationHeader
    } else {
      if (authorizationHeader) {
        header = authorizationHeader
      } else if (signatureHeader) {
        header = signatureHeader
      }
    }
    if (digestHeader) {
      const doesDigestVerify: boolean = HttpKeyPairAuthorizer.doesDigestVerify(httpRequest.body, digestHeader);
      if (!doesDigestVerify) {
        return false;
      }
    }
    return HttpKeyPairAuthorizer.doesSignatureHeaderVerify(header, httpRequest, publicKey);
  }

  static getAuthorizationParametersFromSignatureHeader(signatureHeader: string): Record<string,any> {
    /**
     * Convert a raw signature header to its component data
     *
     * @public method
     * @param {string} The HTTP signature header
     * @return {Record<string,any>} A dictionary of key/value pairs
     */
    const authorizationParameters: Record<string,any> = {};
    const signatureDataString: string = signatureHeader.substring(signatureHeader.indexOf(' ') + 1);
    const signatureData: string[] = signatureDataString.split(',');

    signatureData.forEach((item: string, index: number) => {
      const splitPoint: number = item.indexOf('=');
      const key = item.substring(0, splitPoint).trim();
      let value: any = item.substring(splitPoint + 1).trim();
      if (value[0] === '"') {
        value = value.substring(1, value.length - 1);
      } else {
        const lowercaseValue: string = value.toLowerCase();
        if (lowercaseValue == 'true') {
          value = true
        } else if (lowercaseValue == 'false') {
          value = false
        } else {
          const numericValue: number = parseFloat(value);
          if (!Number.isNaN(numericValue)) {
            value = numericValue
          }
        }
      }
      authorizationParameters[key] = value;
    });
    // if no headers are specified, the default is to find a HTTP Date header
    if (!authorizationParameters.headers) {
      authorizationParameters.headers = 'Date';
    }
    const requiredAuthorizationHeaders: string[] = authorizationParameters.headers.split(' ');
    authorizationParameters.headers = requiredAuthorizationHeaders;
    return authorizationParameters;
    /* */
  }

  static __getRequestTarget(httpRequest: HttpRequest): string {
    /**
     * Build an authorization-compatible (request-target) string, such as 'post /path/to/endpoint?query=param'
     *
     * @private
     * @param {HttpRequest} The HTTP request to process
     * @return {string} The authorization-compatible (request-target) string.
     */
    return `${httpRequest.method.toLowerCase()} ${httpRequest.path}`;
  }

  static exportPrivateKeyToPemString (privateKey: typeof crypto.PrivateKeyObject): string {
    /**
     * Export a private key to a PKCS #8 compatible PEM string
     *
     * @public
     * @param {crrypto.PrivateKey} a private key
     * @return {string}
     */
     let type: string = '';
     if (privateKey.asymmetricKeyType == 'rsa') {
       type = 'pkcs1'
     } else {
       type = 'spki'
     }
     const privateKeyPem: typeof crypto.PrivateKeyObject = privateKey.export({
         type: type,
         format: 'pem'
     })
     return privateKeyPem
  }

  static exportPublicKeyToPemString (publicKey: typeof crypto.PublicKeyObject): string {
    /**
     * Export a public key to a SPKI compatible PEM string
     *
     * @public
     * @param {crypto.PublicKey} a public key
     * @return {string}
     */
     const publicKeyPem: typeof crypto.PublicKeyObject = publicKey.export({
         type: 'spki',
         format: 'pem'
     })
     return publicKeyPem
  }

  static importPrivateKeyFromPemString (pemString: string, algorithmParameters: any): typeof crypto.PrivateKeyObject {
    /**
     * Import a CryptoKey private key from a PKCS #8 compatible PEM string.
     *
     * @public
     * @param {string} The PKCS #8 encoded PEM string
     * @param {any} The name of the algorithm or a dictionary of algorithm parameters such as {name: hash: }. See [SubtleCrypto.importKey() Supported Formats](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#supported_formats) for more information
     * @return {Promise} that's resolved with a {CryptoKey}
     */
     const privateKey: typeof crypto.PrivateKeyObject = crypto.createPrivateKey({
       key: pemString,
       format: 'pem',
       encoding: 'utf-8'
     });
     return privateKey;
  }

  static importPublicKeyFromPemString (pemString: string, algorithmParameters: any): typeof crypto.PublicKeyObject {
    /**
     * Import a CryptoKey public key from a SPKI compatible PEM string.
     *
     * @public
     * @param {string} The SPKI encoded PEM string
     * @param {any} The name of the algorithm or a dictionary of algorithm parameters such as {name: hash: }. See [SubtleCrypto.importKey() Supported Formats](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#supported_formats) for more information
     * @return {Promise} that's resolved with a {CryptoKey}
     */
     const publicKey: typeof crypto.PublicKeyObject = crypto.createPublicKey({
       key: pemString,
       format: 'pem',
       type: 'spki',
       encoding: 'utf-8'
     })
     return publicKey;
  }

}
