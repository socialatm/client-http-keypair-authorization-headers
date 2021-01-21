const crypto = require('crypto')
const { Hash } = require('crypto')
const { Sign } = require('crypto')
// const { PrivateKeyObject, PublicKeyObject } = require('crypto')
// const { subtle } = require('crypto').webcrypto;


exports.printMsg = function () {
  console.log('client-http-drf-keypair-permissions is loaded')
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

  public modulusLength: number  = 4096;
  public publicKeyType: string = 'spki';
  public privateKeyType: string = 'pkcs8';
  public privateKeyFormat: string = 'pem';
  /* Access supported ciphers with `crypto.getCiphers()` */
  public privateKeyCipher: string = 'aes-256-cbc';
  private __privateKeyPassphrase: string;

  public defaultPassphraseLength: number = 20;

  constructor () {
    /**
     * Create a new CavageHttpAuthorizer
     */
    this.privateKeyPassphrase = this.generatePrivateKeyPassphrase();
  }

  get privateKeyPassphrase (): string {
    /**
     * Retrieve the privateKeyPassphrase, used for generating new keypairs
     *
     * @return {string} the instance's private key passphrase
     */
    return this.__privateKeyPassphrase;
  }

  set privateKeyPassphrase (passphrase: string) {
    /**
     * Set the instance's private key passphrase for generating new keypairs
     *
     * @param {string} set the instance's passphrase. A null value will generate a random passphrase
     */
    if (passphrase) {
      this.__privateKeyPassphrase = this.generatePrivateKeyPassphrase(this.defaultPassphraseLength);
    } else {
      this.__privateKeyPassphrase = passphrase;
    }
  }

  generatePrivateKeyPassphrase (length=20): string {
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
    let result: string = '';
    const characters: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    const charactersLength: number = characters.length;
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }

  createSigningMessage(httpRequest: HttpRequest, authorizationParameters?: Record<string,any>): string {
    /**
     * Create the string that will be signed, from the HTTP headers.
     *
     * @public
     * @param {HttpRequest} The HTTP Request information including the headers
     * @param {Record<string, any>} the extra Authorization string parameters which will be included, such as `created` or `expires` timestamps
     * @param {string[]} An ordered list of headers to use to bulid the signing message
     * @return {string} the signing message
     */
    const httpHeaders = httpRequest.headers;
    const signingRows: string[] = [];
    if (authorizationParameters.headers && authorizationParameters.headers.length > 0) {
      const requiredAuthorizationHeaders: string[] = authorizationParameters.headers;
      for (let i=0; i<requiredAuthorizationHeaders.length; i++) {
        const header: string = requiredAuthorizationHeaders[i];
        if (header[0] === '(') {
          if (header === '(request-target)') {
            const requestTarget = this.__getRequestTarget(httpRequest);
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

  createMessageSignature (httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string,any>): string {
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
    const signingMessage: string = this.createSigningMessage(httpRequest, authorizationParameters);
    const signer: typeof crypto.Sign = crypto.createSign(authorizationParameters.algorithm);
    signer.update(signingMessage);
    signer.end();
    const signature: string = signer.sign(privateKey, 'base64');
    return signature;
  }

  createAuthorizationHeader (httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string,any>): string {
    /**
     * Sign message. Algorithms are available at
     *
     * @public
     * @param {string} The public key to be used
     * @param {string} The algorithm to be used
     * @param {string[]} The header keys to be included in the authorization signature
     * @return {string} The full Authorization HTTP header including algorithm="", keyId="", signature="", and headers="".
     */
    const signature: string = this.createMessageSignature(httpRequest, privateKey, authorizationParameters);
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

  createDigestHeader (text: string, hashAlgorithm: string): string {
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

  digestHttpRequest(httpRequest: HttpRequest, hashAlgorithm: string) {
    /**
     * Create a digest header on a httpRequest
     *
     * @param {HttpRequest} The HTTP Request including a `.body` and `.headers`
     * @param {string} the hash algorithm. Get supported algorithmsfrom `crypto.getHashes()`
     * @return {HttpRequest} An updated dictionary with a `Digest` header
     */
     httpRequest.headers['Digest'] = this.createDigestHeader(httpRequest.body, hashAlgorithm);
     return httpRequest;
  }

  signHttpRequest(httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, authorizationParameters: Record<string,any>, digestHashAlgorithm?: string): HttpRequest {
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
      httpRequest.headers['Digest'] = this.createDigestHeader(httpRequest.body, digestHashAlgorithm);
    }
    const authorizationHeader: string = this.createAuthorizationHeader(httpRequest, privateKey, authorizationParameters);
    httpRequest.headers['Authorization'] = authorizationHeader;
    httpRequest.headers['Signature'] = authorizationHeader;
    return httpRequest;
  }

  doesDigestVerify (text: string, digest: string): boolean {
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
    const expectedDigestHeader: string = this.createDigestHeader(text, hashAlgorithm)
    const doesVerify: boolean = (digest == expectedDigestHeader);
    return doesVerify;
  }

  doesSignatureHeaderVerify (header: string, httpRequest: HttpRequest, publicKey: typeof crypto.PublicKeyObject): boolean {
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
     const authorizationParameters: Record<string,any> = this.getAuthorizationParametersFromSignatureHeader(header);
     const requiredAuthorizationHeaders: string[] = authorizationParameters.headers;
     const currentTimestamp: number = Math.floor(Date.now() / 1000) - (60 * 60 * 24);
     // if an authorizationParameters.created exists, make sure it's not in the future
     if (requiredAuthorizationHeaders.includes('(created)')) {
       if (!authorizationParameters.created) {
         return false;
       } else {
         const created: number = parseInt(authorizationParameters.created)
         if (created == NaN || created > currentTimestamp) {
           return false;
         }
       }
     }
     // if an authorizationParameters.expires exists, make sure it's not in the past
     if (requiredAuthorizationHeaders.includes('(expires)')) {
       if (!authorizationParameters.created) {
         return false;
       } else {
         const expires: number = parseInt(authorizationParameters.expires)
         if (expires == NaN || expires < currentTimestamp) {
           return false;
         }
       }
     }
     const signingMessage = this.createSigningMessage(httpRequest, authorizationParameters);
     const doesVerify = crypto.verify(
       authorizationParameters.algorithm,
       Buffer.from(signingMessage),
       {
         key: publicKey,
       },
       Buffer.from(authorizationParameters.signature, 'base64')
     );
     return doesVerify;
  }

  doesHttpRequestVerify (httpRequest: HttpRequest, publicKey: typeof crypto.PublicKeyObject): boolean {
    /**
     * Verify an entire HttpRequest.  There should be identical `Authorization` and `Signature` headers
     *
     * @public
     * @param {HttpRequest} The HTTP request information including a body, headers, and more.
     * @param {crypto.PublicKeyObject} A public key to verify the signature
     * @return {boolean} `true` if HttpRequest verifies, `false` otherwise
     */
    const authorizationHeader = httpRequest.headers['Authorization'];
    const signatureHeader = httpRequest.headers['Signature'];
    const digestHeader = httpRequest.headers['Digest'];
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
      const doesDigestVerify: boolean = this.doesDigestVerify(httpRequest.body, digestHeader);
      if (!doesDigestVerify) {
        return false;
      }
    }
    return this.doesSignatureHeaderVerify(authorizationHeader, httpRequest, publicKey);
  }

  getAuthorizationParametersFromSignatureHeader(signatureHeader: string): Record<string,any> {
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
      const splitPoint = item.indexOf('=');
      const key: string = item.substring(0, splitPoint).trim();
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
          if (numericValue != NaN) {
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

  __getRequestTarget(httpRequest: HttpRequest): string {
    /**
     * Build an authorization-compatible (request-target) string, such as 'post /path/to/endpoint?query=param'
     *
     * @private
     * @param {HttpRequest} The HTTP request to process
     * @return {string} The authorization-compatible (request-target) string.
     */
    return `${httpRequest.method.toLowerCase()} ${httpRequest.path}`;
  }

}


// const auth = CavageHttpAuthorizer()
