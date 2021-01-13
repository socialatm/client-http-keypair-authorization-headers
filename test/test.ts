export {}

const crypto = require('crypto');
const { PublicKeyObject, PrivateKeyObject } = require('crypto')
const assert = require('assert')
const chai = require('chai');
const should = require('chai').should();
const expect = require('chai').expect;
const { HttpMethod, HttpHeaders, HttpRequest } = require('../src/http-keypair-auth');
const HttpKeyPairAuthorizer = require('../src/http-keypair-auth').default;
//import { HttpKeyPairAuthorizer, HttpMethod, HttpHeaders, HttpRequest } from '../src/index';
const deepEqualInAnyOrder = require('deep-equal-in-any-order');
chai.use(deepEqualInAnyOrder);


const authorizer: typeof HttpKeyPairAuthorizer = new HttpKeyPairAuthorizer();

const privateKeyString: string = '-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
  '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\n' +
  '-----END ENCRYPTED PRIVATE KEY-----\n';
const passphrase: string = 'I6lL3W7o3HAnpXldcdWm';
const cipher: string = '';
const privateKey: typeof crypto.PrivateKeyObject = crypto.createPrivateKey({
  key: privateKeyString,
  passphrase: passphrase,
  cipher: authorizer.privateKeyCipher
});

const publicKeyString: string = '-----BEGIN PUBLIC KEY-----\n' +
  'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxkkSR5n3vYheqbXrI8rB\n' +
  '+Yj7tWqhL8QUjdfPBQ+SoGmL8IFr7JVhYCBr11xfbT6PxoWeVRnYwcEg/VJsbMb8\n' +
  'y/nCi6BsiKH7yAxjBumC1Yud68foMwkDCgXe8pKRkB89d8tiWu3WMsdXHIlAIID4\n' +
  'Jsp8gFit5bA8xrNvrA+XphrY9na56OWNeQ3+/ktfqWE3MXjMht5y7Aje09v2oTik\n' +
  'a0ANwhXimWOsaVOAk+YU293+C/dSaO+c1K04FSjNv5L7lWvRcmjz8CGwoH4f+ztF\n' +
  'Dn4RrYTZe9KHASON4SufE6jxEO2d2V62+ffoEcCMlpSOw9uBz2CzkJHDkWPvQ9sJ\n' +
  'cI2LWjJ+WCig4hKmho2aV9duqOlgyO7aWgZI7Rrvlt1gl8xur9fqkE/JYVPQo4Y7\n' +
  'n5Ijg/5OFIoh5IHTmEeONjJqueyfIYRUkOoYpdEfgCNoYFNmqOAHNtz4PQdQTWcb\n' +
  'vH4rEyiV2xL9GpVQCjj6JB1HwbIl0rFUXFJ2KaBdeTdFPv4aW3Kd2YkLFP8AujyA\n' +
  'mkiV9Bnat1PAfEkKJJM2uk7TZNcKTmFCBoqVMjB5S4OQprzGzOTrQFS3H+XFVO99\n' +
  'kKC2Mm2hrGg9UVXc0kP4gqXPgkURkPnGdFs3yNcQkeesOV0hlOuqW8fOzIum7e7x\n' +
  'lk0QSPNm3b6GUJjPJ6pFG60CAwEAAQ==\n' +
  '-----END PUBLIC KEY-----\n';
const publicKey: typeof crypto.PublicKeyObject = crypto.createPublicKey({
  key: publicKeyString,
  type: 'pkcs1',
  format: 'pem',
  encoding: 'base64'
});
const keyId: string = 'keyId';

describe('Gets (request-target) from HttpRequest', () => {
  const httpRequest: typeof HttpHeaders = {
    method: HttpMethod.Get,
    path: '/foo?param=value&pet=dog',
    headers: {},
    body: ""
  };
  const expectedRequestTarget: string = 'get /foo?param=value&pet=dog';
  it('Can create a (request-target) from HttpRequest', () => {
    const requestTarget: string = authorizer.__getRequestTarget(httpRequest);
    requestTarget.should.equal(expectedRequestTarget);
  });
});

describe('Passphrase', () => {
  describe('Generate passphrase:', () => {
    const passphrase: string = authorizer.generatePrivateKeyPassphrase();
    it('passphrases should exist', () => {
      passphrase.should.exist;
    });
    it('passphrases should be a string', () => {
      const passphraseType: string = typeof(passphrase);
      passphraseType.should.equal('string');
    });
    it('passphrases should be of length `.defaultPassphraseLength`', () => {
      passphrase.length.should.equal(authorizer.defaultPassphraseLength)
    });
  })
  describe('Save passphrase:', () => {
    const authorizer: typeof HttpKeyPairAuthorizer = new HttpKeyPairAuthorizer();
    it ('can store a passphrase', () => {
      const passphrase: string = authorizer.generatePrivateKeyPassphrase();
      authorizer.privateKeyPassphrase = passphrase;
      it('passphrases should match', () => {
        passphrase.should.equal(authorizer.passphrase);
      })
    });
  });
});

describe('Digests', () => {
    const authorizer: typeof HttpKeyPairAuthorizer = new HttpKeyPairAuthorizer();
    const staticDigestHeader: string = 'SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=';
    const httpBody: string = '{"hello": "world"}';
    describe(`Can create a digest from a HttpRequest body`, () => {
      const hashAlgorithm: string = 'SHA256';
      const digest: string = authorizer.createDigestHeader(httpBody, hashAlgorithm);
      it(`Generates valid ${hashAlgorithm} hash`, () => {
        digest.should.equal(staticDigestHeader)
      });
    });
    describe(`Verifies digests`, () => {
      const goodDigest: string = authorizer.doesDigestVerify(httpBody, staticDigestHeader);
      it(`Matching digests return true`, () => {
        goodDigest.should.be.true;
      });
      const alteredHttpBody: string = '{"goodbye": "world"}';
      const badDigest: string = authorizer.doesDigestVerify(alteredHttpBody, staticDigestHeader);
      it(`Mismatched digest returns false`, () => {
        badDigest.should.be.false;
      });
    });
});


describe('Signing messages', () => {
  describe('Throws error if no "date" header', () => {
    const httpBody: string = '{"hello": "world"}';
    const httpRequest: typeof HttpHeaders = {
      method: HttpMethod.Get,
      path: '/foo?param=value&pet=dog',
      headers: {},
      body: httpBody
    };
    const authorizationParameters: Record<string,any> = {
      keyId: keyId,
      algorithm: 'rsa-sha256'
    };
    it('Error thrown', () => {
      expect(() => {
        authorizer.createSigningMessage(
          httpRequest,
          authorizationParameters
        )
      }).to.throw(Error, 'Date');
    });
  });
  describe('Can create a "default" singing message from HttpRequest', () => {
    const httpBody: string = '{"hello": "world"}';
    const httpRequest: typeof HttpHeaders = {
      method: HttpMethod.Get,
      path: '/foo?param=value&pet=dog',
      headers: {
        Date: 'Mon, 11 Jan 2021 20:54:32 GMT', // (new Date()).toUTCString(),
      },
      body: httpBody
    };
    const authorizationParameters: Record<string,any> = {
      keyId: keyId,
      algorithm: 'rsa-sha256'
    };
    const signingMessage: string = authorizer.createSigningMessage(httpRequest, authorizationParameters);
    it('message verifies', () => {
      const expectedSigningMessage = `date: Mon, 11 Jan 2021 20:54:32 GMT`
      signingMessage.should.equal(expectedSigningMessage);
    });
  });
  describe('Can create a "basic" singing message HttpRequest', () => {
    const httpBody: string = '{"hello": "world"}';
    const httpRequest: typeof HttpHeaders = {
      method: HttpMethod.Get,
      path: '/foo?param=value&pet=dog',
      headers: {
        'Host': 'example.com',
        'Date': 'Mon, 11 Jan 2021 20:54:32 GMT', // (new Date()).toUTCString(),
        'Content-Type': 'application/json; encoding=utf-8',
        'Accept': 'application/json',
        'Content-Length': httpBody.length * 2
      },
      body: httpBody
    };
    const authorizationParameters: Record<string,any> = {
      created: 1610312072, // Math.floor(Date.now() / 1000) - (60 * 60 * 24),
      expires: 1610484872, // Math.floor(Date.now() / 1000) + (60 * 60 * 24),
      headers: [
        '(request-target)',
        'host',
        'date',
      ]
    };
    const signingMessage: string = authorizer.createSigningMessage(httpRequest, authorizationParameters);
    it('message verifies', () => {
      const expectedSigningMessage: string = `(request-target): get /foo?param=value&pet=dog
host: example.com
date: Mon, 11 Jan 2021 20:54:32 GMT`;
      signingMessage.should.equal(expectedSigningMessage);
    });
  });
  describe('Can create an "all headers" singing message HttpRequest', () => {
    const requestDate: string = (new Date()).toUTCString();
    const currentTimestamp: number = Math.floor(Date.now() / 1000);
    const httpBody: string = '{"hello": "world"}';
    const httpRequest: typeof HttpHeaders = {
      method: HttpMethod.Get,
      path: '/foo?param=value&pet=dog',
      headers: {
        'Host': 'example.com',
        'Date': requestDate,
        'Content-Type': 'application/json; encoding=utf-8',
        'Accept': 'application/json',
        'Content-Length': httpBody.length * 2
      },
      body: httpBody
    };
    const createdTimestamp: number = currentTimestamp - (60 * 60 * 24);
    const expiresTimestamp: number = currentTimestamp + (60 * 60 * 24);
    const authorizationParameters: Record<string,any> = {
      created: createdTimestamp,
      expires: expiresTimestamp,
      headers: [
        '(request-target)',
        '(created)',
        '(expires)',
        'host',
        'date',
        'content-type',
        'content-length'
      ]
    };
    const signingMessage: string = authorizer.createSigningMessage(httpRequest, authorizationParameters);
    it('message verifies', () => {
      const expectedSigningMessage: string = `(request-target): get /foo?param=value&pet=dog
(created): ${createdTimestamp}
(expires): ${expiresTimestamp}
host: example.com
date: ${requestDate}
content-type: application/json; encoding=utf-8
content-length: 36`;
      signingMessage.should.equal(expectedSigningMessage);
    });
  });
});

describe('HTTP authorization signatures', () => {
  describe('Can parse authorization signatures', () => {
    it('Parses "default" signature', () => {
      const signature: string = 'Signature keyId="Test",algorithm="rsa-sha256",signature="abc123"';
      const expectedResult: Record<string,any> = {
        keyId: 'Test',
        algorithm: 'rsa-sha256',
        headers: [
          'Date'
        ],
        signature: 'abc123'
      }
      const result: Record<string,any> = authorizer.getAuthorizationParametersFromSignatureHeader(signature);
      expect(result).to.deep.equalInAnyOrder(expectedResult);
    });
    it('Parses "basic" signature', () => {
      const signature: string = 'Signature keyId="Test",algorithm="rsa-sha256",headers="(request-target) host date",signature="abc123"';
      const expectedResult: Record<string,any> = {
        keyId: 'Test',
        algorithm: 'rsa-sha256',
        headers: [
          '(request-target)',
          'host',
          'date',
        ],
        signature: 'abc123'
      }
      const result: Record<string,any> = authorizer.getAuthorizationParametersFromSignatureHeader(signature);
      expect(result).to.deep.equalInAnyOrder(expectedResult);
    });
    it('Parses "all headers" signature', () => {
      const signature: string = 'Signature keyId="Test",algorithm="rsa-sha256",created=1402170695, expires=1402170699,headers="(request-target) (created) (expires) host date content-type digest content-length",signature="abc123"';
      const expectedResult: Record<string,any> = {
        keyId: 'Test',
        algorithm: 'rsa-sha256',
        created: 1402170695,
        expires: 1402170699,
        headers: [
          '(request-target)',
          '(created)',
          '(expires)',
          'host',
          'date',
          'content-type',
          'digest',
          'content-length'
        ],
        signature: 'abc123'
      }
      const result: Record<string,any> = authorizer.getAuthorizationParametersFromSignatureHeader(signature);
      expect(result).to.deep.equalInAnyOrder(expectedResult);
    });
  })

});

describe('Message signatures', () => {
  const httpBody: string = '{"hello": "world"}';
  const hashAlgorithm: string = 'SHA256';
  describe('Signature creation', () => {
    const httpRequest: typeof HttpHeaders = {
      method: HttpMethod.Get,
      path: '/foo?param=value&pet=dog',
      headers: {
        'Host': 'example.com',
        'Date': 'Mon, 11 Jan 2021 20:54:32 GMT', // (new Date()).toUTCString(),
        'Content-Type': 'application/json; encoding=utf-8',
        'Accept': 'application/json',
        'Content-Length': httpBody.length * 2
      },
      body: httpBody
    };
    const authorizationParameters: Record<string,any> = {
      created: 1610312072, // Math.floor(Date.now() / 1000) - (60 * 60 * 24),
      expires: 1610484872, // Math.floor(Date.now() / 1000) + (60 * 60 * 24)
      algorithm: hashAlgorithm,
      headers: [
        '(request-target)',
        '(created)',
        '(expires)',
        'host',
        'date',
        'content-type',
        'content-length'
      ]
    };
    const messageSignature: string = authorizer.createMessageSignature(
      httpRequest,
      privateKey,
      authorizationParameters
    );
    it('signature is a string', () => {
      const messageSignatureType: string = typeof(messageSignature);
      messageSignatureType.should.equal('string');
    });
    it('signature is valid', () => {
      const expectedSignature: string = 'BCekw5snRmcyEnpWLFiKKFXBXG8miig5EhvQs9Da6mLedOOzrnt+1u5OViFgFn2tqGEHgCdDNebp/+AWQFVpUSO1NpUDmYkvw0IHQNH6JBgKEn6AsyiWEV/SK48ZHElwYU8yjVH3ZBwCPYgkVAIldyDJrSHCKNY8AlayC+OwZwm05Zm/oJkobbyU/j5v27VmfyE1NJ7YnZjssuQmIN67wkKcwkGyHTh4fCQcmBQo4YbfjOHVL/vX7zabmEiWLfGbdNVCq9oN+gAP7dDeQxM5KOW4v/HTH1MP3eFYZoWRZitOlNFBHIBRa0KKqnWB43oM7IN1jSrmgIgcx64UxvSJPrjX4JKygFlaqXgKD8EBYqEU85mf1XGIWvzfP3stsDfuL5XxG8bDg41EnshBgkYYXbdgUeQ4sSoQiGvT8IX2JbZrohQdmGFK4pTa/IqyVjMzzV5DUKIL62WOOfjb9JaZ8ttc+RxCT9DS+Qm9UWM7l1yBlrUztEKJ3iM+CGRL1HP3i92hA63IVfOqnud7dGppIEVygfMwEtlpENvSZBT6KyPuyDXRB59x9yuwCZvlAe9RYv/5XlV2JCgewstYpJU4kyiPX3Z5BxrRwApZT9c6IjEfA2wVm1pipnzCAJe90QNoJ4fBc11EIPd8wTKHxOo2KLqVAGsZAAqAvLGTXZvXPqg='
      messageSignature.should.equal(expectedSignature)
    });
  });
  describe('Signature verification', () => {
    it('Returns false if HTTP headers missing', () => {
      let httpRequest: typeof HttpHeaders = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Host': 'example.com',
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT', // (new Date()).toUTCString(),
          'Content-Type': 'application/json; encoding=utf-8',
          'Accept': 'application/json',
          'Content-Length': httpBody.length * 2,
          'E-Tag': '1234'
        },
        body: httpBody
      };
      const authorizationParameters: Record<string,any> = {
        created: 1610312072, // Math.floor(Date.now() / 1000) - (60 * 60 * 24),
        expires: 1610484872, // Math.floor(Date.now() / 1000) + (60 * 60 * 24)
        keyId: keyId,
        algorithm: hashAlgorithm,
        headers: [
          '(request-target)',
          '(created)',
          '(expires)',
          'host',
          'date',
          'content-type',
          'content-length',
          'e-tag',
        ]
      };
      const header: string = authorizer.createAuthorizationHeader(
        httpRequest,
        privateKey,
        authorizationParameters
      );
      httpRequest = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Host': 'example.com',
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT', // (new Date()).toUTCString(),
          'Content-Type': 'application/json; encoding=utf-8',
          'Accept': 'application/json',
          'Content-Length': httpBody.length * 2
        },
        body: httpBody
      };
      const doesVerify: string = authorizer.doesSignatureHeaderVerify(
        header,
        httpRequest,
        publicKey
      );
      doesVerify.should.be.false;
    });
    it('Returns false if authorization parameters headers missing', () => {
      let httpRequest: typeof HttpHeaders = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Host': 'example.com',
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT', // (new Date()).toUTCString(),
          'Content-Type': 'application/json; encoding=utf-8',
          'Accept': 'application/json',
          'Content-Length': httpBody.length * 2
        },
        body: httpBody
      };
      const authorizationParameters: Record<string,any> = {
        keyId: keyId,
        algorithm: hashAlgorithm,
        headers: [
          '(request-target)',
          '(expires)',
          'host',
          'date',
          'content-type',
          'content-length',
        ]
      };
      let header: string = authorizer.createAuthorizationHeader(
        httpRequest,
        privateKey,
        authorizationParameters
      );
      header = `${header.substring(0, header.length - 1)} (created)"`;
      const doesVerify: string = authorizer.doesSignatureHeaderVerify(
        header,
        httpRequest,
        publicKey
      );
      doesVerify.should.be.false;
    });
    it('Returns false if created in the future', () => {
      let httpRequest: typeof HttpHeaders = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Host': 'example.com',
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT', // (new Date()).toUTCString(),
          'Content-Type': 'application/json; encoding=utf-8',
          'Accept': 'application/json',
          'Content-Length': httpBody.length * 2,
        },
        body: httpBody
      };
      const authorizationParameters: Record<string,any> = {
        created:  Math.floor(Date.now() / 1000) + (60 * 60 * 24),
        keyId: keyId,
        algorithm: hashAlgorithm,
        headers: [
          '(created)'
        ]
      };
      const header: string = authorizer.createAuthorizationHeader(
        httpRequest,
        privateKey,
        authorizationParameters
      );
      const doesVerify: string = authorizer.doesSignatureHeaderVerify(
        header,
        httpRequest,
        publicKey
      );
      doesVerify.should.be.false;
    });
    it('Returns false if expires in the past', () => {
      let httpRequest: typeof HttpHeaders = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT',
        },
        body: httpBody
      };
      const authorizationParameters: Record<string,any> = {
        expires: Math.floor(Date.now() / 1000) - (60 * 60 * 24),
        keyId: keyId,
        algorithm: hashAlgorithm,
        headers: [
          '(expires)'
        ]
      };
      const header: string = authorizer.createAuthorizationHeader(
        httpRequest,
        privateKey,
        authorizationParameters
      );
      const doesVerify: string = authorizer.doesSignatureHeaderVerify(
        header,
        httpRequest,
        publicKey
      );
      doesVerify.should.be.false;
    });
    it('Returns false if no Date HTTP header and empty headers key', () => {
      let httpRequest: typeof HttpHeaders = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT',
        },
        body: httpBody
      };
      const authorizationParameters: Record<string,any> = {
        keyId: keyId,
        algorithm: hashAlgorithm
      };
      const header: string = authorizer.createAuthorizationHeader(
        httpRequest,
        privateKey,
        authorizationParameters
      );
      httpRequest.headers = {};
      const doesVerify: string = authorizer.doesSignatureHeaderVerify(
        header,
        httpRequest,
        publicKey
      );
      doesVerify.should.be.false;
    });
    it('Returns false if signature cannot be verified', () => {
      let httpRequest: typeof HttpHeaders = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT',
        },
        body: httpBody
      };
      const staticHeader: string = 'Signature algorithm="SHA256",keyId="keyId",signature="wGSJE1xujF5WpDyfcOOBCwmgeFV9o6vGwLljc9wcsGUiI2uyHDQN/2CI+YleFT2sR+znOb1imEjJ/QjGxZwGR1IaeHu4x/+eJUVeerCAlQqW7LJDVdsaW9P2A+T+L5Ev6Vcn4CA+Kv/gdulYhUl+uQ2ZcusMMMQjInq7d+DbyM4MNC+GK+TJpbpzJoVAOu6L7A5B02nJ8Nezz5bwo39iavRXCtekk7j7x+j7KwXyCTSKUcvX9ext6+IByrlaGFXGzmUc94WtYBSVfu1rh0gWQdUeklfIq4KlFQjQQAEpQJSbY2OWVpWT0o12NPC3heaFT7l7viy+g/+5/273nJjZCxjGUBbMZkb1Sc96LWVL23hhr5rYZ3CjVc+Q1OVi/uSkATrR3Ovl1y5kfjgw/QrB4OQ9oT+u4hU//1Pqindp1mOwnlJXG2HObl+vBfgxrKd31eJ2q1uXfjSd0rrWpfAoWxBF2lcmp4eLBQpWTe9m4h/EWhacxRhAYvefkszpA4HY5rNUYTECbjK5NPMYJ2fe5nBTAAQkvg3O3+aRm6KQLU2LPlfxKDCHN9vLwD2DWYzY78ndEX4cPvA6NevBlE7ZUcfnCwxmKwQpeU6hJs980RNjSFfG3MZxQJxfBn5N4K5qGzjcwDpGRKmCY79NnOEfu0MJtSFSKZszVOcEwr9/Tck=",created=1610398006,expires=1610570806,headers="(request-target) (created) (expires) host date content-type content-length"';
      const doesVerify: string = authorizer.doesSignatureHeaderVerify(
        staticHeader,
        httpRequest,
        publicKey
      );
      doesVerify.should.be.false;
    });
    it('Returns true if if signature can be verified', () => {
      let httpRequest: typeof HttpHeaders = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Host': 'example.com',
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT',
          'Content-Type': 'application/json; encoding=utf-8',
          'Content-Length': httpBody.length * 2
        },
        body: httpBody
      };
      const createdTimestamp: number = Math.floor(Date.now() / 1000) - (60 * 60 * 24)
      const expiresTimestamp: number = Math.floor(Date.now() / 1000) + (60 * 60 * 24)
      const authorizationParameters: Record<string,any> = {
        created: createdTimestamp,
        expires: expiresTimestamp,
        keyId: keyId,
        algorithm: hashAlgorithm,
        headers: [
          '(request-target)',
          '(created)',
          '(expires)',
          'host',
          'date',
          'content-type',
          'content-length',
        ]
      };
      const staticSignature: string = authorizer.createAuthorizationHeader(
        httpRequest,
        privateKey,
        authorizationParameters
      );
      const doesVerify: string = authorizer.doesSignatureHeaderVerify(
        staticSignature,
        httpRequest,
        publicKey
      );
      doesVerify.should.be.true;
    });
  });
  describe('Verifies HTTP Requests', () => {
    it('Returns true on valid HttpRequest', () => {
      let httpRequest: typeof HttpHeaders = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Host': 'example.com',
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT',
          'Content-Type': 'application/json; encoding=utf-8',
          'Content-Length': httpBody.length * 2,
          'Digest': authorizer.createDigestHeader(httpBody, 'SHA256')
        },
        body: httpBody
      };
      const createdTimestamp: number = Math.floor(Date.now() / 1000) - (60 * 60 * 24)
      const expiresTimestamp: number = Math.floor(Date.now() / 1000) + (60 * 60 * 24)
      const authorizationParameters: Record<string,any> = {
        created: createdTimestamp,
        expires: expiresTimestamp,
        keyId: keyId,
        algorithm: hashAlgorithm,
        headers: [
          '(request-target)',
          '(created)',
          '(expires)',
          'host',
          'date',
          'content-type',
          'content-length',
          'digest'
        ]
      };
      const signature: string = authorizer.createAuthorizationHeader(
        httpRequest,
        privateKey,
        authorizationParameters
      );
      httpRequest.headers['Authorization'] = signature
      httpRequest.headers['Signature'] = signature
      const doesVerify: string = authorizer.doesHttpRequestVerify(
        httpRequest,
        publicKey
      );
      doesVerify.should.be.true;
    });
    it('Returns false on on mismatched Authorization and Signature headers', () => {
      let httpRequest: typeof HttpHeaders = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Host': 'example.com',
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT',
          'Content-Type': 'application/json; encoding=utf-8',
          'Content-Length': httpBody.length * 2
        },
        body: httpBody
      };
      const createdTimestamp: number = Math.floor(Date.now() / 1000) - (60 * 60 * 24)
      const expiresTimestamp: number = Math.floor(Date.now() / 1000) + (60 * 60 * 24)
      const authorizationParameters: Record<string,any> = {
        created: createdTimestamp,
        expires: expiresTimestamp,
        keyId: keyId,
        algorithm: hashAlgorithm,
        headers: [
          '(request-target)',
          '(created)',
          '(expires)',
          'host',
          'date',
          'content-type',
          'content-length',
        ]
      };
      const signature: string = authorizer.createAuthorizationHeader(
        httpRequest,
        privateKey,
        authorizationParameters
      );
      httpRequest.headers['Authorization'] = signature
      httpRequest.headers['Signature'] = signature + '-'
      const doesVerify: string = authorizer.doesHttpRequestVerify(
        httpRequest,
        publicKey
      );
      doesVerify.should.be.false;
    });
    it('Returns false if authorization invalid', () => {
      let httpRequest: typeof HttpHeaders = {
        method: HttpMethod.Get,
        path: '/foo?param=value&pet=dog',
        headers: {
          'Host': 'example.com',
          'Date': 'Mon, 11 Jan 2021 20:54:32 GMT',
          'Content-Type': 'application/json; encoding=utf-8',
          'Content-Length': httpBody.length * 2
        },
        body: httpBody
      };
      const createdTimestamp: number = Math.floor(Date.now() / 1000) - (60 * 60 * 24)
      const expiresTimestamp: number = Math.floor(Date.now() / 1000) + (60 * 60 * 24)
      const authorizationParameters: Record<string,any> = {
        created: createdTimestamp,
        expires: expiresTimestamp,
        keyId: keyId,
        algorithm: hashAlgorithm,
        headers: [
          '(request-target)',
          '(created)',
          '(expires)',
          'host',
          'date',
          'content-type',
          'content-length',
        ]
      };
      const signature: string = authorizer.createAuthorizationHeader(
        httpRequest,
        privateKey,
        authorizationParameters
      );
      httpRequest.headers['Authorization'] = signature
      httpRequest.headers['Signature'] = signature
      httpRequest.headers['Host'] = 'anotherexample.com'
      const doesVerify: string = authorizer.doesHttpRequestVerify(
        httpRequest,
        publicKey
      );
      doesVerify.should.be.false;

    });
  });
});


describe('Http authorization headers', () => {
  const httpBody: string = '{"hello": "world"}';
  const hashAlgorithm = 'SHA256';
  const httpRequest: typeof HttpHeaders = {
    method: HttpMethod.Get,
    path: '/foo?param=value&pet=dog',
    headers: {
      'Host': 'example.com',
      'Date': 'Mon, 11 Jan 2021 20:54:32 GMT', // (new Date()).toUTCString(),
      'Content-Type': 'application/json; encoding=utf-8',
      'Accept': 'application/json',
      'Content-Length': (httpBody.length * 2).toString()
    },
    body: httpBody
  };
  const authorizationParameters: Record<string,any> = {
    created: 1610312072, // Math.floor(Date.now() / 1000) - (60 * 60 * 24),
    expires: 1610484872, // Math.floor(Date.now() / 1000) + (60 * 60 * 24),
    keyId: keyId,
    algorithm: hashAlgorithm,
    headers: [
      '(request-target)',
      '(created)',
      '(expires)',
      'host',
      'date',
      'content-type',
      'content-length'
    ]
  };
  const header: string = authorizer.createAuthorizationHeader(
    httpRequest,
    privateKey,
    authorizationParameters
  );
  describe('Header creation', () => {
    it('signature is a string', () => {
      const headerType = typeof(header);
      headerType.should.equal('string');
    });
    it('signature is valid', () => {
      const expectedHeader = 'Signature algorithm="SHA256",keyId="keyId",signature="BCekw5snRmcyEnpWLFiKKFXBXG8miig5EhvQs9Da6mLedOOzrnt+1u5OViFgFn2tqGEHgCdDNebp/+AWQFVpUSO1NpUDmYkvw0IHQNH6JBgKEn6AsyiWEV/SK48ZHElwYU8yjVH3ZBwCPYgkVAIldyDJrSHCKNY8AlayC+OwZwm05Zm/oJkobbyU/j5v27VmfyE1NJ7YnZjssuQmIN67wkKcwkGyHTh4fCQcmBQo4YbfjOHVL/vX7zabmEiWLfGbdNVCq9oN+gAP7dDeQxM5KOW4v/HTH1MP3eFYZoWRZitOlNFBHIBRa0KKqnWB43oM7IN1jSrmgIgcx64UxvSJPrjX4JKygFlaqXgKD8EBYqEU85mf1XGIWvzfP3stsDfuL5XxG8bDg41EnshBgkYYXbdgUeQ4sSoQiGvT8IX2JbZrohQdmGFK4pTa/IqyVjMzzV5DUKIL62WOOfjb9JaZ8ttc+RxCT9DS+Qm9UWM7l1yBlrUztEKJ3iM+CGRL1HP3i92hA63IVfOqnud7dGppIEVygfMwEtlpENvSZBT6KyPuyDXRB59x9yuwCZvlAe9RYv/5XlV2JCgewstYpJU4kyiPX3Z5BxrRwApZT9c6IjEfA2wVm1pipnzCAJe90QNoJ4fBc11EIPd8wTKHxOo2KLqVAGsZAAqAvLGTXZvXPqg=",created=1610312072,expires=1610484872,headers="(request-target) (created) (expires) host date content-type content-length"';
      header.should.equal(expectedHeader);
    });
  });
});

describe('HttpRequest tests', () => {
  describe('Creates and Verifies Digest', () => {
    const httpBody: string = '{"hello": "world"}';
    const hashAlgorithm: string = 'SHA256';
    const httpRequest: typeof HttpHeaders = {
      method: HttpMethod.Get,
      path: '/foo?param=value&pet=dog',
      headers: {
        'Host': 'example.com',
        'Date': 'Mon, 11 Jan 2021 20:54:32 GMT', // (new Date()).toUTCString(),
        'Content-Type': 'application/json; encoding=utf-8',
        'Accept': 'application/json',
        'Content-Length': (httpBody.length * 2).toString()
      },
      body: httpBody
    };
    const authorizationParameters: Record<string,any> = {
      created: 1610312072, // Math.floor(Date.now() / 1000) - (60 * 60 * 24),
      expires: 1610484872, // Math.floor(Date.now() / 1000) + (60 * 60 * 24)
      keyId: keyId,
      algorithm: hashAlgorithm,
      headers: [
        '(request-target)',
        '(created)',
        '(expires)',
        'host',
        'date',
        'content-type',
        'content-length'
      ]
    };
    it('Creates and verifies signature and digest on a HTTP request', () => {
      const digestHashAlgorithm: string = 'sha256';
      const updatedHttpRequest: typeof HttpRequest = authorizer.digestHttpRequest(
        httpRequest,
        digestHashAlgorithm
      )
      const doesVerify: boolean = authorizer.doesDigestVerify(
        updatedHttpRequest.body,
        updatedHttpRequest.headers['Digest']
      )
      doesVerify.should.be.true

    });
  });
  describe('Signs and Verifies HTTP Request', () => {
    const httpBody: string = '{"hello": "world"}';
    const hashAlgorithm = 'SHA256';
    const httpRequest: typeof HttpHeaders = {
      method: HttpMethod.Get,
      path: '/foo?param=value&pet=dog',
      headers: {
        'Host': 'example.com',
        'Date': 'Mon, 11 Jan 2021 20:54:32 GMT', // (new Date()).toUTCString(),
        'Content-Type': 'application/json; encoding=utf-8',
        'Accept': 'application/json',
        'Content-Length': (httpBody.length * 2).toString()
      },
      body: httpBody
    };
    const authorizationParameters: Record<string,any> = {
      created: 1610312072, // Math.floor(Date.now() / 1000) - (60 * 60 * 24),
      expires: 1610484872, // Math.floor(Date.now() / 1000) + (60 * 60 * 24)
      keyId: keyId,
      algorithm: hashAlgorithm,
      headers: [
        '(request-target)',
        '(created)',
        '(expires)',
        'host',
        'date',
        'content-type',
        'content-length'
      ]
    };
    const digestHashAlgorithm: string = 'sha256';
    it('Signs and verifies HTTP request', () => {
      const updatedHttpRequest: typeof HttpRequest = authorizer.signHttpRequest(
        httpRequest,
        privateKey,
        authorizationParameters
      )
      const doesVerify: boolean = authorizer.doesHttpRequestVerify(
        updatedHttpRequest,
        publicKey,
      )
      doesVerify.should.be.true
    });
    it('Signs and digests and verifies HTTP request', () => {
      const updatedHttpRequest: typeof HttpRequest = authorizer.signHttpRequest(
        httpRequest,
        privateKey,
        authorizationParameters,
        digestHashAlgorithm
      )
      const doesVerify: boolean = authorizer.doesHttpRequestVerify(
        updatedHttpRequest,
        publicKey
      )
      doesVerify.should.be.true
    });
  });
});
/* */
