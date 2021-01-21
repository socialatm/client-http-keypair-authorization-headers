'use strict'

/**
 * CavageHttpAuthorizer creates Cavage-compatible
 * HTTP authorization headers.
 *
 * @class
 * @constructor
 * @public
 */
class HttpKeyPairAuthorizer {

  static get KEY_TYPE_PUBLIC () { return 'public' }
  static get KEY_TYPE_PRIVATE () { return 'private' }

  static createDigest (text, hashAlgorithm) {
    /**
     * Create a digest from a string. hashes are available at crypt.getHashes()
     *
     * @public
     * @param {string} The hashing algorithm to use, eg 'sha256' or 'sha512'
     * @param {string} The text to be digested
     * @return {string} A promise that resolves with hash digest of the text variable
     */
    return new Promise((resolve) => {
      var encoder = new TextEncoder()
      window.crypto.subtle.digest(hashAlgorithm, encoder.encode(text)).then(response => {
        var digest = window.btoa(String.fromCharCode.apply(null, new Uint8Array(response)))
        resolve(digest)
      })
    })
  }

  static createDigestHeader (text, hashAlgorithm) {
    /**
     * Create a digest from a string. hashes are available at crypt.getHashes()
     *
     * @public
     * @param {string} The hashing algorithm to use, eg 'sha256' or 'sha512'
     * @param {string} The text to be digested
     * @return {string} A hash digest of the text variable
     */
    return new Promise((resolve) => {
      this.createDigest(text, hashAlgorithm).then(digest => {
        var header = `${hashAlgorithm.toUpperCase()}=${digest}`
        resolve(header)
      })
    })
  }

  static createSigningMessage (httpRequest, authorizationParameters = null) {
    /**
     * Create the string that will be signed, from the HTTP headers.
     *
     * @public
     * @param {HttpRequest} The HTTP Request information including the headers
     * @param {Record<string, any>} the extra Authorization string parameters which will be included, such as `created` or `expires` timestamps
     * @param {string[]} An ordered list of headers to use to bulid the signing message
     * @return {string} the signing message
     */
    var httpHeaders = httpRequest.headers
    var signingRows = []
    if (authorizationParameters.headers && authorizationParameters.headers.length > 0) {
      var requiredAuthorizationHeaders = authorizationParameters.headers
      for (var i = 0; i < requiredAuthorizationHeaders.length; i++) {
        var header = requiredAuthorizationHeaders[i]
        if (header[0] === '(') {
          if (header === '(request-target)') {
            var requestTarget = this.__getRequestTarget(httpRequest)
            signingRows.push(`${header}: ${requestTarget}`)
          } else {
            var cleanedHeader = header.substring(1, header.length - 1)
            signingRows.push(`${header}: ${authorizationParameters[cleanedHeader]}`)
          }
        } else {
          var cleanedHeader = header.toLowerCase().split('-').map((word, index) => {
            return word.replace(word[0], word[0].toUpperCase())
          }).join('-')
          signingRows.push(`${header}: ${httpHeaders[cleanedHeader]}`)
        }
      }
    } else {
      if (httpHeaders && httpHeaders.Date) {
        signingRows.push(`date: ${httpHeaders.Date}`)
      } else {
        throw Error('If no authorizationParameters.headers are specified, a "Date" HTTP header must exist to create')
      }
    }
    var signingMessage = signingRows.join('\n')
    return signingMessage
  }

  static createMessageSignature (httpRequest, privateKey, authorizationParameters) {
    /**
     * Create the message signature. This function only supports ECDSA hash algorithms. Ge
     *
     * @private
     * @param {HttpRequest} An object containing information about HTTP request headers, method, and body.
     * @param {crypto.PrivateKeyObject} The private key used to create the signature
     * @param {string} the hashing algorithm. Get a list of supported hashing algorithms from crypto.getHashes()
     * @param {Record<string: string>} A dictionary of headers and pseudo-headers which will be used to build the message to be signed
     * @return {string} A signature created from the parameters provided
     */
    /*
    var algorithmParameters = {
      name: 'ECDSA',
      hash: { name: authorizationParameters.algorithm }
    }
    /* */
    var algorithmParameters = authorizationParameters.algorithmParameters
    var signingMessage = this.createSigningMessage(httpRequest, authorizationParameters)
    var encoder = new TextEncoder()
    return new Promise(resolve => {
      window.crypto.subtle.sign(algorithmParameters, privateKey, encoder.encode(signingMessage)).then(response => {
        var signature = window.btoa(String.fromCharCode.apply(null, new Uint8Array(response)))
        resolve(signature)
      })
    })
  }

  static createAuthorizationHeader (httpRequest, privateKey, authorizationParameters) {
    /**
     * Sign message. Algorithms are available at
     *
     * @public
     * @param {string} The public key to be used
     * @param {string} The algorithm to be used
     * @param {string[]} The header keys to be included in the authorization signature
     * @return {string} The full Authorization HTTP header including algorithm="", keyId="", signature="", and headers="".
     */
    return new Promise(resolve => {
      this.createMessageSignature(httpRequest, privateKey, authorizationParameters).then(response => {
        var signature = response
        console.log('signature')
        console.log(signature)
        var signatureHeaders = {}
        var authorizationHeaderString = ''
        if (authorizationParameters) {
          for (var key in authorizationParameters) {
            if (key !== 'headers' && key !== 'algorithmParameters') {
              signatureHeaders[key] = authorizationParameters[key]
            }
          }
          if (authorizationParameters.headers) {
            authorizationHeaderString = authorizationParameters.headers.map((key, index) => {
              return key
            }).join(' ')
          }
        }
        console.log(authorizationParameters)
        if (authorizationParameters.algorithmParameters.hash === 'SHA-1') {
          signatureHeaders.algorithm = 'RSA-SHA1'
        } else if (authorizationParameters.algorithmParameters.hash === 'SHA-256') {
          signatureHeaders.algorithm = 'RSA-SHA256'
        } else if (authorizationParameters.algorithmParameters.hash === 'SHA-384') {
          signatureHeaders.algorithm = 'RSA-SHA384'
        } else if (authorizationParameters.algorithmParameters.hash === 'SHA-512') {
          signatureHeaders.algorithm = 'RSA-SHA512'
        }
        signatureHeaders.signature = signature
        // we can omit the headers="" if it's only Date
        if (authorizationHeaderString !== 'Date') {
          signatureHeaders.headers = authorizationHeaderString
        }
        var signatureHeader = Object.keys(signatureHeaders).map((key, index) => {
          var value = signatureHeaders[key]
          var output = ''
          if (typeof value === 'string') {
            output = `${key}="${value}"`
          } else {
            output = `${key}=${value}`
          }
          return output
        }).join(',')
        /* */
        var header = `Signature ${signatureHeader}`
        console.log(header)
        resolve(header)
      })
    })
  }

  static digestHttpRequest (httpRequest, hashAlgorithm) {
    /**
     * Create a digest header on a httpRequest
     *
     * @param {HttpRequest} The HTTP Request including a `.body` and `.headers`
     * @param {string} the hash algorithm. Get supported algorithmsfrom `crypto.getHashes()`
     * @return {HttpRequest} An updated dictionary with a `Digest` header
     */
    return new Promise(resolve => {
      httpRequest.headers.Digest = this.createDigestHeader(httpRequest.body, hashAlgorithm)
      resolve(httpRequest)
    })
  }

  static signHttpRequest (httpRequest, privateKey, authorizationParameters, digestHashAlgorithm = null) {
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
      return new Promise(resolve => {
        console.log(authorizationParameters)
        this.createDigestHeader(httpRequest.body, digestHashAlgorithm).then(digestHeader => {
          httpRequest.headers.Digest = digestHeader
          this.signHttpRequestAfterDigest(httpRequest, privateKey, authorizationParameters).then(httpResponse => {
            resolve(httpRequest)
          })
        })
      })
    } else {
      return this.signHttpRequestAfterDigest(httpRequest, privateKey, authorizationParameters)
    }
  }

  static signHttpRequestAfterDigest (httpRequest, privateKey, authorizationParameters) {
    /**
     * Create a signed authorization header (and possibly a digest) and place it in the HttpRequest.
     *
     * @param {HttpRequest} The HTTP Request including a `.body` and `.headers`
     * @param {crypto.PrivateKeyObject} The private key which will sign the request
     * @param {string} The key ID as it's known on the server of the signing key's public key
     * @param {string} The algorithm used to sign the message. Get supported algorithms from `crypto.getHashes()`
     * @param {Record<string,any>} The parameters used to generate the signature header
     * @return {HttpRequest} The updated dictionary with `Authorization` and `Signature` headers, and possibly a `Digest` header
     */
    return new Promise(resolve => {
      this.createAuthorizationHeader(httpRequest, privateKey, authorizationParameters).then(authorizationHeader => {
        httpRequest.headers.Authorization = authorizationHeader
        httpRequest.headers.Signature = authorizationHeader
        resolve(httpRequest)
      })
    })
  }

  static __getRequestTarget (httpRequest) {
    /**
     * Build an authorization-compatible (request-target) string, such as 'post /path/to/endpoint?query=param'
     *
     * @private
     * @param {HttpRequest} The HTTP request to process
     * @return {string} The authorization-compatible (request-target) string.
     */
    return `${httpRequest.method.toLowerCase()} ${httpRequest.path}`
  }

  static __arrayBufferToString (buf) {
    /**
     * Convert an array buffer to a string.
     *
     * @private
     * @param {ArrayBuffer} the inbound array buffer
     * @return {string}
     */
    return String.fromCharCode.apply(null, new Uint8Array(buf))
  }

  static __stringToArrayBuffer (str) {
    /**
     * Convert a string to an array buffer.
     *
     * @private
     * @param {string} the string to convert
     * @return {ArrayBuffer}
     */
    var buf = new ArrayBuffer(str.length)
    var bufView = new Uint8Array(buf)
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i)
    }
    return buf
  }

  static __addNewlines (str, lineLength) {
    /**
     * Add newlines every `lineLength` characters
     *
     * @private
     * @param {string} the string to split into lines
     * @param {number} The number of characters between line breaks
     * @return {string}
     */
    let result = ''
    while (str.length > 0) {
      result += str.substring(0, lineLength) + '\n'
      str = str.substring(lineLength)
    }
    return result
  }

  static exportPrivateKeyToPemString (privateKey) {
    /**
     * Export a private key to a PKCS #8 compatible PEM string
     *
     * @public
     * @param {CryptoKey} a private key
     * @return {string}
     */
    return this.__exportKeyToPemString(HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE, privateKey)
  }

  static exportPublicKeyToPemString (publicKey) {
    /**
     * Export a public key to a SPKI compatible PEM string
     *
     * @public
     * @param {CryptoKey} a public key
     * @return {string}
     */
    return this.__exportKeyToPemString(HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC, publicKey)
  }

  static __exportKeyToPemString (keyType, privateKey) {
    /**
     * Export a key to a PEM string
     *
     * @private
     * @param {CryptoKey} a private key
     * @return {string} must be HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC or HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE
     */
    if (![HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC, HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE].includes(keyType)) {
      throw Error('Invalid key format. Must be HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC or HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE')
    }
    var paddingText = ''
    var keyFormat = ''
    if (keyType === HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC) {
      paddingText = 'PUBLIC'
      keyFormat = 'spki'
    } else {
      paddingText = 'PRIVATE'
      keyFormat = 'pkcs8'
    }
    return new Promise(resolve => {
      window.crypto.subtle.exportKey(keyFormat, privateKey).then(response => {
        var pkcs8PrivateKey = response
        var exportedAsString = this.__arrayBufferToString(pkcs8PrivateKey)
        var exportedAsBase64 = window.btoa(exportedAsString)
        var newlineExport = this.__addNewLines(exportedAsBase64)
        var pemExported = `-----BEGIN ${paddingText} KEY-----\n${newlineExport}-----END ${paddingText} KEY-----`
        resolve(pemExported)
      })
    })
  }

  static importPrivateKeyFromPemString (pemString, algorithmParameters) {
    /**
     * Import a CryptoKey private key from a PKCS #8 compatible PEM string.
     *
     * @public
     * @param {string} The PKCS #8 encoded PEM string
     * @param {any} The name of the algorithm or a dictionary of algorithm parameters such as {name: hash: }. See [SubtleCrypto.importKey() Supported Formats](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#supported_formats) for more information
     * @return {Promise} that's resolved with a {CryptoKey}
     */
    return this.__importKeyFromPemString(HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE, pemString, algorithmParameters)
  }

  static importPublicKeyFromPemString (pemString, algorithmParameters) {
    /**
     * Import a CryptoKey public key from a SPKI compatible PEM string.
     *
     * @public
     * @param {string} The SPKI encoded PEM string
     * @param {any} The name of the algorithm or a dictionary of algorithm parameters such as {name: hash: }. See [SubtleCrypto.importKey() Supported Formats](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#supported_formats) for more information
     * @return {Promise} that's resolved with a {CryptoKey}
     */
    return this.__importKeyFromPemString(HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC, pemString, algorithmParameters)
  }

  static __importKeyFromPemString (keyType, pemString, algorithmParameters) {
    /**
     * Import a CryptoKey private key  PEM string.
     *
     * @public
     * @param {string} The PKCS #8 encoded PEM string
     * @param {any} The name of the algorithm or a dictionary of algorithm parameters such as {name: hash: }. See [SubtleCrypto.importKey() Supported Formats](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#supported_formats) for more information
     * @return {Promise} that's resolved with a {CryptoKey}
     */
    if (![HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC, HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE].includes(keyType)) {
      throw Error('Invalid key format. Must be HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC or HttpKeyPairAuthorizer.KEY_TYPE_PRIVATE')
    }
    var keyUses = []
    var keyFormat = ''
    if (keyType === HttpKeyPairAuthorizer.KEY_TYPE_PUBLIC) {
      keyUses.push('verify')
      keyFormat = 'spki'
    } else {
      keyUses.push('sign')
      keyFormat = 'pkcs8'
    }
    var base64Key = pemString.replace(/-{5}(BEGIN|END)([A-Z ]*)KEY-{5}?/g, '')
    var binaryKey = window.atob(base64Key)
    var encodedBinaryKey = this.__stringToArrayBuffer(binaryKey)
    return new Promise((resolve, reject) => {
      window.crypto.subtle.importKey(keyFormat, encodedBinaryKey, algorithmParameters, true, keyUses).then(privateKey => {
        resolve(privateKey)
      }).catch(() => {
        throw Error('Error processing your PEM string into a CryptoKey. Your PEM format is likely incompatible. Make sure it PKCS #8 compatible')
      })
    })
  }
}

/**
 * helper functions, don't belong in the HttpKeyPairAuthorizer class
 */

/*
How to use:

// Get a PEM private key, for example this ECDSA P-256 key
var edcsaP256KeyPem = '-----BEGIN EC PRIVATE KEY-----\n' +
  'MHcCAQEEIG65UDNLeeH2M0FJMq5sS66Zgbfo5HmeiYvSF0rvx+fLoAoGCCqGSM49\n' +
  'AwEHoUQDQgAE+YwQJ7xak48kmy4IhOLo3krj998lCeN95dCTA72TWaHQtwMraLPO\n' +
  'Kc2Z9V6olwQNiezfiSNq83Ln7EL3AOpp9g==\n' +
  '-----END EC PRIVATE KEY-----'

var algorithmParameters = {
  name: 'ECDSA',
  namedCurve: 'P-256'
}

// Load a private key
var privateKey = HttpKeyPairAuthorizer.importPrivateKeyFromPemString(edcsaP256KeyPem, algorithmParameters)

// if you don't have a PEM key to load, you can generate a new one.
// You will also need to register your public key with a server
var keyPair = crypto.subtle.generateKey(
  algorithmParameters,
  true,
  ['sign', 'verify']
).then(keyPair => {
  // store your key pair.
})

// Build a HTTP request
var now = new Date()
var httpBody = '{"hello": "world"}'
var httpRequest = {
  method: 'POST',
  path: '/foo?param=value&pet=dog'
  headers: {
    Host: 'example.com',
    Date: now.toUTCString(),
    'Content-Type': 'application/json; encoding=utf-8',
    'Content-Length': (httpBody.length * 2).toString()
  },
  body: httpBody
}

// Define the authorization parameters for building a signature
// it should be noted that CORS restricts the Date, Host,
// and Content-Length HTTP headers
// Do not include them in cross-origin requests
// keyId is the public key's identifier on the server
var authorizationParameters = {
  keyId: 'Test',
  algorithm: 'SHA256',
  created: Math.floor(now / 1000) - (60 * 60 * 24),
  expires: Math.floor(now / 1000) + (60 * 60 * 24),
  headers: [
    '(request-target)',
    '(created)',
    '(expires)',
    'digest'
  ]
}
var digestHashAlgorithm = 'SHA256'

// A digest will be inserted automatically if 'digest' is in the `.headers` array
// however, if you want to insert a digest manually, you can do this:
httpRequest.headers['Digest'] = HttpKeyPairAuthorizer.createDigestHeader(httpRequest.body, digestHashAlgorithm)

// Update the HTTP request with the header signature
var updatedHttpRequest;
HttpKeyPairAuthorizer.createAuthorizationHeader(
  httpRequest,
  privateKey,
  authorizationParameters,
  digestHashAlgorithm
).then(response => {
  updatedHttpRequest = response
})

// now use your favorite AJAX library to send the HTTP request to a server

/**/
