
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

## Send Requests to a Server

Typically requests are sent from a client to a server, but with this authorization mechanism, it is possible to send authorized messages the other way around.

Clients can create a HTTP header that includes a cryptographic signature of some HTTP headers. This header will include the `keyId`, the server's ID of the client's public key stored on the server.

For added security, the client can create a hash digest of the HTTP body to verify the HTTP body was not altered in transport.


### Create an Authorization header

A client can sign HTTP headers to secure HTTP requests. Each header included provides a different layer of security.

| Header or property | Reason to include                                     |
|--------------------|-------------------------------------------------------|
| (request-target)   | Verifies which endpoint the request was intended for  |
| Host               | Verifies which server the request was intended for    |
| Date               | Verifies that the request is unique                   |
| (created)          | Helps verify that the signature was not forged        |
| (created)          | Helps verify that the signature was not forged        |
| Digest             | Helps verify the message was not altered              |
| Content-Length     | Helps verify the message was not altered              |

Minimally, the `Date` header should be included in the HTTP request and in the signature creation.

#### Default headers example

The default signature will include only the HTTP `Date` header by default. As this header should change with each request, it guarantees that each request has a unique signature.


```js
// if not using in the browser:
import { HttpKeyPairAuthorizer, HttpMethod } from 'client-http-keypair-authorization-headers'

// Load a locally-stored private key
const authorizer = new HttpKeyPairAuthorizer()
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
const updatedHttpRequest = authorizer.createAuthorizationHeader(
  httpRequest,
  privateKey,
  authorizationParameters,
)
console.log(updatedHttpRequest.headers['Authorization']);
// 'algorithm="SHA256",keyId="Test",signature="iKKFBCekw5snRmcyEnpWLFXBXG8miig...",headers="date"'
```

#### Full headers example

This example shows the full headers including a `Digest` (explained below)

```js
// if not using in the browser:
import { HttpKeyPairAuthorizer, HttpMethod } from 'client-http-keypair-authorization-headers'

// load the private key from memory
const authorizer = new HttpKeyPairAuthorizer()
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
const updatedHttpRequest = authorizer.createAuthorizationHeader(
  httpRequest,
  privateKey,
  authorizationParameters,
  digestHashAlgorithm
)
console.log(updatedHttpRequest.headers['Authorization']);
// 'algorithm="SHA256",keyId="keyId",signature="iKKFBCekw5snRmcyEnpWLFXBXG8miig...",created=1234567890,expires=1234567890,headers="(request-target) (created) (expires) host date digest content-type content-length"'
```

### Create a message digest

A message digest can be created to further validate the message body.

The digest will be included in the `Digest` HTTP header and can be bound to the `Authorization` header to make ensure the digest and message body are cryptographically signed.

```js
// if not using in the browser:
import HttpKeyPairAuthorizer from 'client-http-keypair-authorization-headers'

const authorizer = new HttpKeyPairAuthorizer()
const httpBody = '{"hello": "world"}'
const hashAlgorithm = 'SHA256'
const digest = authorizer.createDigestHeader(httpBody, hashAlgorithm)

console.log(digest)
// SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
```


### Using with fetch

```js
const response = await fetch(
  'http://example.com/foo?param=value&pet=dog', {
    method: 'POST',
    headers: {
      'Host': 'example.com',
      'Date': now.toUTCString(),
      'Content-Type': 'application/json; encoding=utf-8',
      'Accept': 'application/json',
      'Content-Length': (httpBody.length * 2).toString(),
      // use one or both of these headers, depending on the server specs
      'Authorization': authorizationHeader,
      'Signature': authorizationHeader,
      // if there is a message digest, put here also
      'Digest': digest,
    },
    body: httpBody
  }
)
```

### Using with Axios

```js
const response = await axios.post(
  'http://example.com/foo?param=value&pet=dog',
  httpBody,
  {
    headers: httpRequest.headers
  }
)
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
const doesVerify: string = authorizer.doesHttpRequestVerify(
  authorizationHeader,
  httpRequest,
  publicKey
)
console.log(doesVerify)
// true
```

The server is responsible for managing the lookup function for the `keyId` and loading a locally stored public key belonging to the client that sent the request.

### Verify Digest

A request may contain a `Digest` header, which verifies the request body was not altered during transit. It is not cryptographically signed, so a middle man may be able to create a new digest.

However, when the `Authorization` header is signed using the  `Digest` header, the request recipient can know that the digest (and therefore the request body) has not been tampered with.

```js
// if not using in the browser:
import HttpKeyPairAuthorizer from 'client-http-keypair-authorization-headers'

const authorizer = new HttpKeyPairAuthorizer()

const staticDigestHeader = 'SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE='
const httpBody = '{"hello": "world"}'
const doesDigestVerify = authorizer.doesDigestVerify(alteredHttpBody, staticDigestHeader)
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
