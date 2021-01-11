# HTTP Cavage public key / private key authorization headers for authorizations

This Django module was created to give "Cavage" HTTP Signatures capabilities to the Django Rest Framework.

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

Browser file can be found in `dist.browser/index.js`

```html
<script src="/path/to/index.js"></script>
```


## Create a message digest

```js
// if not using in the browser:
import { HttpKeyPairAuthorizator } from 'client-http-keypair-authorization-headers'

const authorizer = new HttpKeyPairAuthorizator()
const httpBody = '{"hello": "world"}'
const hashAlgorithm = 'SHA256'
const digest = authorizer.createDigestHeader(httpBody, hashAlgorithm)

console.log(digest)
// SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
```

## Create an Authorization header

```js
// if not using in the browser:
import { HttpKeyPairAuthorizator, HttpMethod } from 'client-http-keypair-authorization-headers'

const authorizer = new HttpKeyPairAuthorizator()
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
    'Host': 'example.com',
    'Date': now.toUTCString(),
    'Content-Type': 'application/json; encoding=utf-8',
    'Accept': 'application/json',
    'Content-Length': (httpBody.length * 2).toString(),
    'Digest': digest
  },
  body: httpBody
}
const authorizationParameters = {
  created: Math.floor(now / 1000) - (60 * 60 * 24),
  expires: Math.floor(now / 1000) + (60 * 60 * 24)
}
const keyId = 'keyId'
const requiredAuthorizationHeaders = [
  '(request-target)',
  '(created)',
  '(expires)',
  'host',
  'date',
  'digest',
  'content-type',
  'content-length'
];
const authorizationHeader = authorizer.createAuthorizationHeader(
  httpRequest,
  privateKey,
  keyId,
  hashAlgorithm,
  authorizationParameters,
  requiredAuthorizationHeaders
)
console.log(authorizationHeader);
// 'algorithm="SHA256",keyId="keyId",signature="iKKFBCekw5snRmcyEnpWLFXBXG8miig...",headers="(request-target) (created) (expires) host date digest content-type content-length"'
```

## Using with fetch

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
      'Digest': digest,
      'Authorization': authorizationHeader
    },
    body: httpBody
  }
);
```

## Using with Axios

```js
const response = await axios.post(
  'http://example.com/foo?param=value&pet=dog',
  httpBody,
  {
    headers: {
      'Host': 'example.com',
      'Date': now.toUTCString(),
      'Content-Type': 'application/json; encoding=utf-8',
      'Accept': 'application/json',
      'Content-Length': (httpBody.length * 2).toString(),
      'Digest': digest,
      'Authorization': authorizationHeader
    }
  }
);
```


## Run unit tests

```
$ npm test
```

## Build

```
$ npm run-script build
```
