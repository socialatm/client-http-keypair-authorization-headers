

# HTTP Cavage public key / private key authorization headers for authorizations


[Cavage HTTP Key-Pair Authorization](https://tools.ietf.org/html/draft-cavage-http-signatures-12) functions as an alternative for API tokens, OAuth, or JWT for REST and GraphQL APIs or web applications.

It works by having a web client sign HTTP headers and/or create a hash digest of the HTTP message body. In doing so, it verifies that the web client is the true creator of the message and that the message has not been tampered with during transport.

It can be used for:

* Authentication and resource access restriction
* Access throttling
* Collecting usage statistics
* and much, much more

Just like in traditional API token or OAuth system, a server expects to verify the the client has permission to access a resource such as a URL endpoint. However, with this system the client can also know if the server is the true creator of the HTTP response and that the message has not been tampered with during transport. Therefore this system creates two-way security for web applications.

### How Traditional API Authorization Works

With API tokens, OAuth and JWT, the server creates a token that is given to the client. The client must store the token and send it to the server with each subsequent request that is verified by the server. If the client loses the token, it no longer has access to the resource. If another client else gains access to the token, the other client can access the resource as if they are the owner of the token.  

### How Key-Pair Authorization Works

With this HTTP key-pair authorization, the client generates a public key and private key. The private key is stored locally but does not need to be sent across the network. The public key is sent one time to the server, where it is stored and given an ID. This id is shared with the client. From there, only the public key ID is used to communicate about the client's public key.

When the client accesses a resource from a server, it makes a list of HTTP headers which will be used to create a cryptographic signature. This signature is signed using the client's private key and the list of headers is sent as a part of the signature. The server sends this list and the key ID it received when it registered its public key with the server in the `Authorization` HTTP header. The server then uses these same headers to verify the signature using the stored public key for that client.

Furthermore, the client can create a hash digest of the message body. The server can verify the hash to know that the message has not been altered since it was created. It can incorporate the digest in the signature to further verify that the digest has not been altered and that the creator of both the digest and the HTTP message body is the client.

This system has the added benefit of being able to work the other way around. It ensures that, once a server's public key is registered in a client application, all subsequent HTTP responses originated from the server.

### How does Key-Pair Authorization Affect HTTP Requests

A normal HTTP Request might look like this:

```
POST /foo?param=value&pet=dog
Host: example.com
Content-Length: 34
Date: Mon, 11 Jan 2021 20:54:32 GMT
Content-Type: application/json; encoding=utf-8
Accept: application/json

{"hello":"world"}
```

In this example, the HTTP client is POSTING some JSON data to the url `http://example.com/foo?param=value&pet=dog`. The HTTP headers include the date and content type.

In HTTP keypair authorization, a subset of HTTP headers are used to create a message that is signed using a private key on the client.  This signature and other information necessary to verify the signature are then described in the `Authorization` and/or `Signature` headers.

The client must share its public key with authorizing sever prior to using HTTP key-pair authorization. This public key is given an ID by the server, which is shared with the client, and which the client uses as a shorthand to tell the server which public key to use when verifying authorization.

Optionally, a digest of the HTTP message body may be included in the `Digest` header and used to create the signature also, to add an extra layer of security. If so, the algorithm is prepended to the digest with the format `ALGORITHM=DIGEST`.

```
POST /foo?param=value&pet=dog
Host: example.com
Content-Length: 34
Date: Mon, 11 Jan 2021 20:54:32 GMT
Content-Type: application/json; encoding=utf-8
Accept: application/json
Digest: SHA512=U0hBLTUxMj16RllORkk1anErY3FoT3ZIK3JSNzFHNmRZMU85bkNjMk9xczdWK0xCbkpYSWVrdEVwWTg4U0swdStjK29LR2xpaEp3NFFMdjc2d21NUHJlTEZmMms5Zz09
Authorization: algorithm="rsa-sha256",keyId="client-public-key-id",expires=1611235402,headers="(request-path) (expires) host content-length date digest",signature="TiJZTTihhUYAIlOm2PpnvJa/+15WOX2U0iKJ2LXsLecvohhRIWnwFfdHy4ci10mcv/UQgf2+bFf9lfFZUlPPdzckBNfXIqAjafM8XquJiw/t1v+pEGtJpaGASlzuWuL37gp3k8ux3l6zBKKbBVPPASkHVhz37uY1AXeMblfRbFE="

{"hello":"world"}
```

The server may then:

* Use the `keyId` in the `Authorization` header to load a locally stored copy of the client's private key,
* Reproduce the singing message by assembling the header and authorization data from the `headers` key
* Verify the `signature` data using the client's public key, and the signing message, using the `algorithm` described in the `Authorization` header.

## Why this library exists

This JavaScript module was created to give "Cavage" HTTP Signatures capabilities AJAX and REST API requests.

This enables HTTP authorization based on public key/private key encryption as an alternative to session cookies or API tokens.

For more information see [Draft Cavage HTTP Signatures 12](https://tools.ietf.org/html/draft-cavage-http-signatures-12)

Using [Django Rest Framework](https://www.django-rest-framework.org/) on the server? Try the [DRF Keypair authorization header library](https://pypi.org/project/drf-keypair-permissions/).


## Installation

**NPM:**

```
npm install --save client-http-keypair-authorization-headers
```

**Yarn:**

```
yarn install --save client-http-keypair-authorization-headers
```

**Browser:**

Browser file can be found in `dist.browser/http-keypair-auth.js`

```html
<script src="/path/to/http-keypair-auth.js"></script>
```

## Creating and Exchanging Key Pairs

In this authorization system, the client must generate its own public and private keys, and then share the public key with the server. The server must store the public key and associate it with the client, and return to the client an ID for that public key.  Of course the client and server must both support the key pair encryption and signature hashing algorithms.

Therefore, it is important to know how to generate a key pair, plus how to export that key pair to a format that can be stored or transferred across a network.

### Generating Key Pairs

**In Node:**
```js
let keyPair = {}
const { generateKeyPair } = require('crypto');
generateKeyPair('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase: 'top secret'
  }
}, (err, publicKey, privateKey) => {
  keyPair = { publicKey: publicKey, privateKey: privateKey };
});
```

**In the browser**

Of course there are many algorithms that can be used to generate a key pair. This example creates an ECDSA-P256 key pair which can be extracted (necessary for saving and sharing) and can be used to both sign and verify signatures (necessary for authorization).
```js
var crypto = window.crypto

var keyPair = await crypto.subtle.generateKey(
  {
    name: 'ECDSA',
    namedCurve: 'P-256'
  }, true, ['sign', 'verify']
)
// resulting keyPair data structure will be: { privateKey: CrytoKey, publicKey: CryptoKey }
```
[More information about SubtleCrypto.generateKey](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey)

### Exporting Keys

**In Node:**

To export a key in Node, the `crypto.PublicKey.export()` and `crypto.PrivateKey.export()` methods may be used.

```js
// export a public key, for storage and sharing with a server
const publicKeyPem = publicKey.export({
    type: 'spki',
    format: 'pem'
})

// export a private key, for storing locally
const privateKeyPem = privateKey.export({
    type: 'pkcs1',
    format: 'pem',
})
```

**In the browser**

```js
// export a public key, for storage and sharing with a server
var publicKeyPem = HttpKeyPairAuthorizer.exportPublicKeyToPemString(
  keyPair.publicKey,
)

// export a private key, for storing locally
var privateKeyPem = HttpKeyPairAuthorizer.exportPrivateKeyToPemString(
  keyPair.privateKey,
)
```

### Importing Keys

**In Node:**

```js
const privateKeyString: string = '-----BEGIN PRIVATE KEY-----\n...'
const passphrase: string = 'I6lL3W7o3HAnpXldcdWm';  // Create a secret passphrase
const cipher: string = 'aes-256-cbc'; // pick a hash from cipher.getHashes()
const privateKey: typeof crypto.PrivateKeyObject = crypto.createPrivateKey({
  key: privateKeyString,
  encoding: 'utf-8'
});

const publicKeyString = '-----BEGIN PUBLIC KEY-----\n...';
const publicKey: typeof crypto.PublicKeyObject = crypto.createPublicKey({
  key: publicKeyString,
  encoding: 'utf-8'
});
```

**In the browser**

On the browser, `algorithmParameters` must be provided, which are compatible with the [importKey supported formats](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#supported_formats)

```js
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

var privateKey = HttpKeyPairAuthorizer.importPrivateKeyFromPemString(
  edcsaP256KeyPem,
  algorithmParameters
)
```

## Send Requests to a Server

Typically requests are sent from a client to a server, but with this authorization mechanism, it is possible to send authorized messages the other way around.

Clients can create a HTTP header that includes a cryptographic signature of some HTTP headers. This header will include the `keyId`, the server's ID of the client's public key stored on the server.

For added security, the client can create a hash digest of the HTTP body to verify the HTTP body was not altered in transport.


### Create an Authorization header

A client can sign HTTP headers to secure HTTP requests. Each header included provides a different layer of security.

| Header or property | Reason to include                                     |Allowed on CORS |
|--------------------|-------------------------------------------------------|----------------|
| (request-target)   | Verifies which endpoint the request was intended for  |Yes          |
| Host               | Verifies which server the request was intended for    |No          |
| Date               | Verifies that the request is unique                   |No          |
| (created)          | Helps verify that the signature was not forged        |Yes         |
| (created)          | Helps verify that the signature was not forged        |Yes         |
| Digest             | Helps verify the message was not altered              |Yes         |
| Content-Length     | Helps verify the message was not altered              |No          |

Minimally, the `Date` header should be included in the HTTP request and in the signature creation.

**Note:** On cross-origin requests (CORS), `Date`, `Host`, and `Content-Length` headers are disallowed

#### Default headers example

The default signature will include only the HTTP `Date` header by default. As this header should change with each request, it guarantees that each request has a unique signature.

**In Node:**

```js
// if not using in the browser:
import { HttpKeyPairAuthorizer, HttpMethod } from 'client-http-keypair-authorization-headers'

// Load a locally-stored private key
const privateKeyString = '-----BEGIN ENCRYPTED PRIVATE KEY-----...'
const passphrase = 'passphrase'
const privateKey = crypto.createPrivateKey({
  key: privateKeyString,
  passphrase: passphrase,
  cipher: 'aes-256-cbc'
})
const httpBody = '{"hello": "world"}'
const hashAlgorithm = 'SHA256'
const now = new Date();
const httpRequest = {
  method: HttpMethod.Post,
  path: '/foo?param=value&pet=dog',
  headers: {
    'Date': now.toUTCString(),
  },
  body: httpBody
}

// describe the
const authorizationParameters = {
  keyId: 'Test', // server's ID for client public key
  algorithm: 'SHA256',
  headers: []
}
const updatedHttpRequest = HttpKeyPairAuthorizer.createAuthorizationHeader(
  httpRequest,
  privateKey,
  authorizationParameters,
)
console.log(updatedHttpRequest.headers['Authorization']);
// 'algorithm="SHA256",keyId="Test",signature="iKKFBCekw5snRmcyEnpWLFXBXG8miig...",headers="date"'
```

**In the browser:**

```js
// Load a private key
const privateKeyString = '-----BEGIN PRIVATE KEY-----...'
var algorithmParameters = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256'
}
var privateKey = HttpKeyPairAuthorizer.importPrivateKeyFromPemString(privateKeyString, algorithmParameters)

// Build a HTTP request
var now = new Date()
var httpBody = '{"hello": "world"}'
var httpRequest = {
  method: 'POST',
  path: '/foo?param=value&pet=dog',
  headers: {
    Date: now.toUTCString(),
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
  headers: []
}
var digestHashAlgorithm = 'SHA256'

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
console.log(updatedHttpRequest.headers['Authorization']);
// 'algorithm="SHA256",keyId="Test",signature="iKKFBCekw5snRmcyEnpWLFXBXG8miig...",headers="date"'
```

#### Full headers example

This example shows the full headers including a `Digest` (explained below)

**In Node:**

```js
// if not using in the browser:
import { HttpKeyPairAuthorizer, HttpMethod } from 'client-http-keypair-authorization-headers'

// load the private key from memory
const privateKeyString = '-----BEGIN ENCRYPTED PRIVATE KEY-----...'
const passphrase = 'passphrase'
const privateKey = crypto.createPrivateKey({
  key: privateKeyString,
  passphrase: passphrase,
  cipher: 'aes-256-cbc'
})

// build a HTTP request
const httpBody = '{"hello": "world"}'
const now = new Date();
const httpRequest = {
  method: HttpMethod.Post,
  path: '/foo?param=value&pet=dog',
  headers: {
    'Host': 'example.com',
    'Date': now.toUTCString(),
    'Content-Type': 'application/json; encoding=utf-8',
    'Accept': 'application/json',
    'Content-Length': (httpBody.length * 2).toString(),
  },
  body: httpBody
}
// Configure signer
const authorizationParameters = {
  keyId: 'Test',
  algorithm: 'SHA256',
  created: Math.floor(now / 1000) - (60 * 60 * 24),
  expires: Math.floor(now / 1000) + (60 * 60 * 24),
  headers: [
    '(request-target)',
    '(created)',
    '(expires)',
    'host',
    'date',
    'digest',
    'content-type',
    'content-length'
  ]
}
const digestHashAlgorithm = 'SHA256'

// Apply signature headers to HTTP request
const updatedHttpRequest = HttpKeyPairAuthorizer.createAuthorizationHeader(
  httpRequest,
  privateKey,
  authorizationParameters,
  digestHashAlgorithm
)
console.log(updatedHttpRequest.headers['Authorization']);
// 'algorithm="SHA256",keyId="keyId",signature="iKKFBCekw5snRmcyEnpWLFXBXG8miig...",created=1234567890,expires=1234567890,headers="(request-target) (created) (expires) host date digest content-type content-length"'
```

**In the browser:**

```js
// if not using in the browser:
// load the private key from memory
const privateKeyString = '-----BEGIN ENCRYPTED PRIVATE KEY-----...'
// Load a private key
var privateKey = HttpKeyPairAuthorizer.importPrivateKeyFromPemString(edcsaP256KeyPem, algorithmParameters)

// Build a HTTP request
var now = new Date()
var httpBody = '{"hello": "world"}'
var httpRequest = {
  method: 'POST',
  path: '/foo?param=value&pet=dog',
  headers: {
    Host: 'example.com',
    Date: now.toUTCString(),
    'Content-Type': 'application/json; encoding=utf-8',
    'Accept': 'application/json',
    'Content-Length': (httpBody.length * 2).toString(),
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
    'host',
    'date',
    'digest',
    'content-type',
    'content-length'
  ]
}
var digestHashAlgorithm = 'SHA256'

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
console.log(updatedHttpRequest.headers['Authorization']);
// 'algorithm="SHA256",keyId="keyId",signature="iKKFBCekw5snRmcyEnpWLFXBXG8miig...",created=1234567890,expires=1234567890,headers="(request-target) (created) (expires) host date digest content-type content-length"'
```

### Create a message digest

A message digest can be created to further validate the message body.

The digest will be included in the `Digest` HTTP header and can be bound to the `Authorization` header to make ensure the digest and message body are cryptographically signed.

**In Node:**

```js
// if not using in the browser:
import HttpKeyPairAuthorizer from 'client-http-keypair-authorization-headers'

const httpBody = '{"hello": "world"}'
const hashAlgorithm = 'SHA-256'
const digest = HttpKeyPairAuthorizer.createDigestHeader(httpBody, hashAlgorithm)

console.log(digest)
// SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
```

**In the Browser:**

```js
var digestHashAlgorithm = 'SHA-256'
HttpKeyPairAuthorizer.createDigestHeader(httpRequest.body, digestHashAlgorithm)
HttpKeyPairAuthorizer.createDigestHeader(httpRequest.body, digestHashAlgorithm).then(response => {
  httpRequest.headers['Digest'] = response
  console.log(response)
})
// SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
```

### Using with fetch

```js
// it should be noted that with CORS requests,
// `Date`, 'Host', and `Content-Length` headers are disabled
// and therefore cannot be included in the signature parameters
const response = await fetch(
  'http://example.com/foo?param=value&pet=dog', {
  mode: 'cors',
  headers: httpRequest.headers,
  body: httpRequest.httpBody
})
```

### Using with Axios

```js
// it should be noted that with CORS requests,
// `Date`, 'Host', and `Content-Length` headers are disabled
// and therefore cannot be included in the signature parameters
const response = await axios({
  method: 'POST',
  url: 'http://example.com/foo?param=value&pet=dog',
  data: httpBody,
  headers: { common: httpRequest.headers }
})
```

### Using with http

```js
const http = require('http')

let req = http.request(httpRequest, (chunk) => {
  // do something  with the inbound data
})

req.write(httpRequest.body)
req.end()
```

## Verify Requests from a Client

When a message is received, it can verify the `Authorization` header to know if the sender and message are valid, authorized, and unmodified. Typically the sender is a client and the receiver is a server, but that is not strictly the case with this authorization mechanism.

Prior to receiving a request, the server must have a local copy of the client's public key and both client and server must agree on a unique ID for that key, as the client must tell the server which public key must be used to verify the signature it created. This guarantees the identify client to the server.

A signature which incorporates a digest makes it possible to verify the authenticity of the request body as well.

## Verify the Signature

A client is expected to send the same data in an `Authorization` and `Signature` HTTP header, which will includes:

* The public key ID as known on the server
* The algorithm used to create the signature
* The HTTP headers and other information used to generate the signed message
* A base64-encoded cryptographic signature
* Possibly the creation and expiration time of the signature

This can all be parsed by the HttpKeyPairAuthorizer class to verify the `Authorization` header.

**In Node:**

```js
// if not using in the browser:
import HttpKeyPairAuthorizer from 'client-http-keypair-authorization-headers'
// crypto library required
import crypto from 'crypto'

// authorizationHeader pulled from a HTTP request
// public key loaded from a locally referenced public key ID, which
// was extracted from the authorizationHeader key="<public key id>"

// look up publicKeyString from keyId, provided in authorization header
const publicKeyString = '-----BEGIN PUBLIC KEY-----...'
// create a crypto.PublicKeyObject
const publicKey = crypto.createPublicKey({
  key: publicKeyString,
  type: keyTypeFromMemory,
  format: 'pem',
  encoding: 'base64'
})

// build a HttpRequest interface
// this example uses hard-coded data
// the actual header data required will be specified in the `headers=""`
// string within the `authorizationHeader`
HttpRequest = {
  method: 'get',
  path: '/local/path?query=parameters',
  headers: {
    'Host': 'example.com',
    'Date': 'Mon, 11 Jan 2021 20:54:32 GMT',
    'Content-Type': 'application/json; encoding=utf-8',
    'Accept': 'application/json',
    'Content-Length': '{"hello": "world"}'.length * 2,
    'Digest': 'abc123',
    'Authorization': authorizationHeader,
    'Signature': authorizationHeader
  },
  body: '{"hello": "world"}'
}

// verify the Authorization header
const doesVerify: string = HttpKeyPairAuthorizer.doesHttpRequestVerify(
  authorizationHeader,
  httpRequest,
  publicKey
)
console.log(doesVerify)
// true
```

**In the browser:**

```js
// authorizationHeader pulled from a HTTP request
// public key loaded from a locally referenced public key ID, which
// was extracted from the authorizationHeader key="<public key id>"

// look up publicKeyString from keyId, provided in authorization header
const publicKeyString = '-----BEGIN PUBLIC KEY-----...'
// create a CryptoKey object
const algorithmParameters = {
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256'
}
const publicKey = await HttpKeyPairAuthorizer.importPublicKeyFromPemString(
  publicKeyString,
  algorithmParameters
)

// build a HttpRequest interface
// this example uses hard-coded data
// the actual header data required will be specified in the `headers=""`
// string within the `authorizationHeader`
httpRequest = {
  method: 'get',
  path: '/local/path?query=parameters',
  headers: {
    'Host': 'example.com',
    'Date': 'Mon, 11 Jan 2021 20:54:32 GMT',
    'Content-Type': 'application/json; encoding=utf-8',
    'Accept': 'application/json',
    'Content-Length': '{"hello": "world"}'.length * 2,
    'Digest': 'abc123',
    'Authorization': authorizationHeader,
    'Signature': authorizationHeader
  },
  body: '{"hello": "world"}'
}

// verify the Authorization header
const doesVerify = await HttpKeyPairAuthorizer.doesHttpRequestVerify(
  authorizationHeader,
  httpRequest,
  publicKey
)
console.log(doesVerify)
// true
```

The server is responsible for managing the lookup function for the `keyId` and loading a locally stored public key belonging to the client that sent the request.

### Verify Digest

*This feature is currently not available in the browser.*

A request may contain a `Digest` header, which verifies the request body was not altered during transit. It is not cryptographically signed, so a middle man may be able to create a new digest.

However, when the `Authorization` header is signed using the  `Digest` header, the request recipient can know that the digest (and therefore the request body) has not been tampered with.

**In Node**

```js
// if not using in the browser:
import HttpKeyPairAuthorizer from 'client-http-keypair-authorization-headers'

const staticDigestHeader = 'SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE='
const httpBody = '{"hello": "world"}'
const doesDigestVerify = HttpKeyPairAuthorizer.doesDigestVerify(httpBody, staticDigestHeader)
console.log(doesDigestVerify)
// true
```

**In the browser:**

```js
const staticDigestHeader = 'SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE='
const httpBody = '{"hello": "world"}'
const doesDigestVerify = await HttpKeyPairAuthorizer.doesDigestVerify(httpBody, staticDigestHeader)
console.log(doesDigestVerify)
// true
```

# Known Issues

Right now, HTTP headers in the `HttpRequest` and `HttpHeaders` objects are case-sensitive, and are expected to be in `Title-Case`. `lower-case`, `UPPER-CASE`, or `mIXed-cAse` will result in the HttpKeyPairAuthorizer being unable to find the right headers when generating signatures.


# Building

```
$ npm run-script build
```

# Running unit tests

```
$ npm test

  Gets (request-target) from HttpRequest
    ✓ Can create a (request-target) from HttpRequest

  Passphrase
    Generate passphrase:
      ✓ passphrases should exist
      ✓ passphrases should be a string
      ✓ passphrases should be of length `.defaultPassphraseLength`
    Save passphrase:
      ✓ can store a passphrase

  Digests
    Can create a digest from a HttpRequest body
      ✓ Generates valid SHA256 hash
    Verifies digests
      ✓ Matching digests return true
      ✓ Mismatched digest returns false

  Signing messages
    Throws error if no "date" header
      ✓ Error thrown
    Can create a "default" singing message from HttpRequest
      ✓ message verifies
    Can create a "basic" singing message HttpRequest
      ✓ message verifies
    Can create an "all headers" singing message HttpRequest
      ✓ message verifies

  HTTP authorization signatures
    Can parse authorization signatures
      ✓ Parses "default" signature
      ✓ Parses "basic" signature
      ✓ Parses "all headers" signature

  Message signatures
    Signature creation
      ✓ signature is a string
      ✓ signature is valid
    Signature verification
      ✓ Returns false if HTTP headers missing
      ✓ Returns false if authorization parameters headers missing
      ✓ Returns false if created in the future
      ✓ Returns false if expires in the past
      ✓ Returns false if no Date HTTP header and empty headers key
      ✓ Returns false if signature cannot be verified
      ✓ Returns true if if signature can be verified
    Verifies HTTP Requests
      ✓ Returns true on valid HttpRequest
      ✓ Returns false on on mismatched Authorization and Signature headers
      ✓ Returns false if authorization invalid

  Http authorization headers
    Header creation
      ✓ signature is a string
      ✓ signature is valid

  HttpRequest tests
    Creates and Verifies Digest
      ✓ Creates and verifies signature and digest on a HTTP request
    Signs and Verifies HTTP Request
      ✓ Signs and verifies HTTP request
      ✓ Signs and digests and verifies HTTP request
```

## Thank you

If you enjoy this tool, please feel free to support me

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/S6S53GD2U)
