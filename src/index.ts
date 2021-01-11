const crypto = require('crypto')
const { Hash } = require('crypto')
// const { PrivateKeyObject, PublicKeyObject } = require('crypto')

exports.printMsg = function () {
  console.log('client-http-drf-keypair-permissions is loaded')
}
/*
interface KeyPair {
  publicKey: typeof PublicKeyObject;
  privateKey: typeof PrivateKeyObject;
}
/* */

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
 * @class
 * @constructor
 * @public
 */
export class HttpKeyPairAuthorizator {

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

  get privateKeyPassphrase () {
    /**
     * Retrieve the privateKeyPassphrase, used for generating new keypairs
     * @return {string} the instance's private key passphrase
     */
    return this.__privateKeyPassphrase;
  }

  set privateKeyPassphrase (passphrase: string) {
    /**
     * Set the instance's private key passphrase for generating new keypairs
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

  createMessageSignature (httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, hashAlgorithm: string, authorizationParameters: Record<string,any>, requiredAuthorizationHeaders?: string[]): string {
    /**
     * Create the message signature
     * @public
     */
    const httpHeaders = httpRequest.headers;
    const signingRows: string[] = [];
    if (requiredAuthorizationHeaders && requiredAuthorizationHeaders.length > 0) {
      for (let i=0; i<requiredAuthorizationHeaders.length; i++) {
        const header: string = requiredAuthorizationHeaders[i];
        if (header[0] == '(') {
          if (header == '(request-target)') {
            const requestTarget = `${httpRequest.method.toLowerCase()} ${httpRequest.path}`;
            signingRows.push(`${header}: ${requestTarget}`)
          } else {
            const cleanedHeader: string = header.substr(1, header.length - 2)
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
      if (authorizationParameters.created) {
        signingRows.push(`(created): ${authorizationParameters.created}`);
      } else if (httpHeaders.Date) {
        signingRows.push(`date: ${httpHeaders.Date}`);
      } else {
        throw 'Date or created authorizationParameters required'
      }
    }
    const signingString: string = signingRows.join('\n');
    // return signingString
    /*
    const signature = crypto.sign(hashAlgorithm, Buffer.from(signingString), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    }).toString('base64');
    /* */
    const signer = crypto.createSign(hashAlgorithm);
    signer.update(signingString);
    signer.end();
    const signature = signer.sign(privateKey, 'base64');
    return signature;
    /* */

  }

  createAuthorizationHeader (httpRequest: HttpRequest, privateKey: typeof crypto.PrivateKeyObject, keyId: string, hashAlgorithm: string, authorizationParameters: Record<string,any>, requiredAuthorizationHeaders: string[]): string {
    /**
     * Sign message. Algorithms are available at
     * @param {string} The public key to be used
     * @param {string} The algorithm to be used
     * @param {string[]} The header keys to be included in the authorization signature
     */
    const signature: string = this.createMessageSignature (httpRequest, privateKey, hashAlgorithm, authorizationParameters, requiredAuthorizationHeaders);
    const authorizationHeaderString: string = requiredAuthorizationHeaders.map((key: string, index: number) => {
      return key;
    }).join(' ');
    const signatureHeaders: Record<string,any> = {
      algorithm: hashAlgorithm,
      keyId: keyId,
      signature: signature,
      headers: authorizationHeaderString
    };
    const signatureHeader: string = Object.keys(signatureHeaders).map( (key: string, index: number) => {
      const value: string = signatureHeaders[key];
      return `${key}="${value}"`;
    }).join(',');
    /* */
    return signatureHeader;
  }

  createDigestHeader (text: string, hashAlgorithm: string): string {
    /**
     * Create a digest from a string. hashes are available at crypt.getHashes()
     * @param {string} The hashing algorithm to use, eg 'sha256' or 'sha512'
     * @param {string} The text to be digested
     */
    const digester: typeof Hash = crypto.createHash(hashAlgorithm);
    const digest: string = digester.update(text).digest('base64');
    const header = `${hashAlgorithm}=${digest}`;
    return header
  }

}


// const auth = CavageHttpAuthorizer()
