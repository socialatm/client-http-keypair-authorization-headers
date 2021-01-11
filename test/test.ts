export {}

const crypto = require('crypto');
const { PublicKeyObject, PrivateKeyObject } = require('crypto')
const assert = require('assert')
var should = require('chai').should();
const { HttpKeyPairAuthorizator, HttpMethod, HttpHeaders, HttpRequest } = require('../src/index');
//import { HttpKeyPairAuthorizator, HttpMethod, HttpHeaders, HttpRequest } from '../src/index';

describe('Passphrase', () => {
  describe('Generate passphrase:', () => {
    const authorizer: typeof HttpKeyPairAuthorizator = new HttpKeyPairAuthorizator();
    const passphrase: string = authorizer.generatePrivateKeyPassphrase();
    it('passphrases should exist', () => {
      passphrase.should.exist;
    });
    it('passphrases should be a string', () => {
      const passphraseType = typeof(passphrase);
      passphraseType.should.equal('string');
    });
    it('passphrases should be of length `.defaultPassphraseLength`', () => {
      passphrase.length.should.equal(authorizer.defaultPassphraseLength)
    });
  })
  describe('Save passphrase:', () => {
    const authorizer: typeof HttpKeyPairAuthorizator = new HttpKeyPairAuthorizator();
    it ('can store a passphrase', () => {
      const passphrase: string = authorizer.generatePrivateKeyPassphrase();
      authorizer.privateKeyPassphrase = passphrase;
      it('passphrases should match', () => {
        passphrase.should.equal(authorizer.passphrase);
      })
    });
  });
});

/*
describe('Keypairs', () => {
  describe('Can generate keypairs', () => {
    const authorizer: typeof HttpKeyPairAuthorizator = new HttpKeyPairAuthorizator();
    const keypair: typeof KeyPair = authorizer.generateKeyPair('rsa')
    it('public key exists', () => {
      const publicKeyType = typeof(keypair.publicKey);
      publicKeyType.should.equal(typeof PublicKeyObject);
    });
    it('private key exists', () => {
      const privateKeyType = typeof(keypair.privateKey);
      privateKeyType.should.equal(typeof PrivateKeyObject);
    });
  });
});
/* */

describe('Digests', () => {
    const authorizer: typeof HttpKeyPairAuthorizator = new HttpKeyPairAuthorizator();
    // const keypair: KeyPair = authorizer.generateKeyPair('rsa')
    const httpBody: string = '{"hello": "world"}';
    describe(`Can generate digests`, () => {
      const hashAlgorithm: string = 'SHA256';
      const digest: string = authorizer.createDigestHeader(httpBody, hashAlgorithm);
      it(`Generates valid ${hashAlgorithm} hash`, () => {
        digest.should.equal('SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=')
      });
    });
});


describe('Message signature', () => {
  const authorizer: typeof HttpKeyPairAuthorizator = new HttpKeyPairAuthorizator();
  // const keypair: typeof KeyPair = authorizer.generateKeyPair('rsa')
  /*
  const keyPair: typeof KeyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
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
  /* */
  const privateKeyString: string = '-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
    '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\n' +
    '-----END ENCRYPTED PRIVATE KEY-----\n'
  const passphrase: string = 'I6lL3W7o3HAnpXldcdWm';
  const cipher: string = '';
  const privateKey = crypto.createPrivateKey({
    key: privateKeyString,
    passphrase: passphrase,
    cipher: authorizer.privateKeyCipher
  });
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
      'Content-Length': httpBody.length * 2
    },
    body: httpBody
  };
  const authorizationParameters: Record<string,any> = {
    created: 1610312072, // Math.floor(Date.now() / 1000) - (60 * 60 * 24),
    expires: 1610484872 // Math.floor(Date.now() / 1000) + (60 * 60 * 24)
  };
  const requiredAuthorizationHeaders: string[] = [
    '(request-target)',
    '(created)',
    '(expires)',
    'host',
    'date',
    'content-type',
    'content-length'
  ];
  const messageSignature: string = authorizer.createMessageSignature(
    httpRequest,
    privateKey,
    hashAlgorithm,
    authorizationParameters,
    requiredAuthorizationHeaders
  );
  it('signature is a string', () => {
    const messageSignatureType = typeof(messageSignature);
    messageSignatureType.should.equal('string');
  });
  it('signature is valid', () => {
    const expectedSignature = 'BCekw5snRmcyEnpWLFiKKFXBXG8miig5EhvQs9Da6mLedOOzrnt+1u5OViFgFn2tqGEHgCdDNebp/+AWQFVpUSO1NpUDmYkvw0IHQNH6JBgKEn6AsyiWEV/SK48ZHElwYU8yjVH3ZBwCPYgkVAIldyDJrSHCKNY8AlayC+OwZwm05Zm/oJkobbyU/j5v27VmfyE1NJ7YnZjssuQmIN67wkKcwkGyHTh4fCQcmBQo4YbfjOHVL/vX7zabmEiWLfGbdNVCq9oN+gAP7dDeQxM5KOW4v/HTH1MP3eFYZoWRZitOlNFBHIBRa0KKqnWB43oM7IN1jSrmgIgcx64UxvSJPrjX4JKygFlaqXgKD8EBYqEU85mf1XGIWvzfP3stsDfuL5XxG8bDg41EnshBgkYYXbdgUeQ4sSoQiGvT8IX2JbZrohQdmGFK4pTa/IqyVjMzzV5DUKIL62WOOfjb9JaZ8ttc+RxCT9DS+Qm9UWM7l1yBlrUztEKJ3iM+CGRL1HP3i92hA63IVfOqnud7dGppIEVygfMwEtlpENvSZBT6KyPuyDXRB59x9yuwCZvlAe9RYv/5XlV2JCgewstYpJU4kyiPX3Z5BxrRwApZT9c6IjEfA2wVm1pipnzCAJe90QNoJ4fBc11EIPd8wTKHxOo2KLqVAGsZAAqAvLGTXZvXPqg='
    messageSignature.should.equal(expectedSignature)
  })
});


describe('Http Header', () => {
  const authorizer: typeof HttpKeyPairAuthorizator = new HttpKeyPairAuthorizator();
  const privateKeyString: string = '-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
    '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\n' +
    '-----END ENCRYPTED PRIVATE KEY-----\n'
  const passphrase: string = 'I6lL3W7o3HAnpXldcdWm';
  const privateKey = crypto.createPrivateKey({
    key: privateKeyString,
    passphrase: passphrase,
    cipher: authorizer.privateKeyCipher
  });
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
    expires: 1610484872 // Math.floor(Date.now() / 1000) + (60 * 60 * 24)
  };
  const keyId: string = 'keyId';
  const requiredAuthorizationHeaders: string[] = [
    '(request-target)',
    '(created)',
    '(expires)',
    'host',
    'date',
    'content-type',
    'content-length'
  ];
  const header: string = authorizer.createAuthorizationHeader(
    httpRequest,
    privateKey,
    keyId,
    hashAlgorithm,
    authorizationParameters,
    requiredAuthorizationHeaders
  );
  it('signature is a string', () => {
    const headerType = typeof(header);
    headerType.should.equal('string');
  });
  it('signature is valid', () => {
    const expectedHeader = 'algorithm="SHA256",keyId="keyId",signature="BCekw5snRmcyEnpWLFiKKFXBXG8miig5EhvQs9Da6mLedOOzrnt+1u5OViFgFn2tqGEHgCdDNebp/+AWQFVpUSO1NpUDmYkvw0IHQNH6JBgKEn6AsyiWEV/SK48ZHElwYU8yjVH3ZBwCPYgkVAIldyDJrSHCKNY8AlayC+OwZwm05Zm/oJkobbyU/j5v27VmfyE1NJ7YnZjssuQmIN67wkKcwkGyHTh4fCQcmBQo4YbfjOHVL/vX7zabmEiWLfGbdNVCq9oN+gAP7dDeQxM5KOW4v/HTH1MP3eFYZoWRZitOlNFBHIBRa0KKqnWB43oM7IN1jSrmgIgcx64UxvSJPrjX4JKygFlaqXgKD8EBYqEU85mf1XGIWvzfP3stsDfuL5XxG8bDg41EnshBgkYYXbdgUeQ4sSoQiGvT8IX2JbZrohQdmGFK4pTa/IqyVjMzzV5DUKIL62WOOfjb9JaZ8ttc+RxCT9DS+Qm9UWM7l1yBlrUztEKJ3iM+CGRL1HP3i92hA63IVfOqnud7dGppIEVygfMwEtlpENvSZBT6KyPuyDXRB59x9yuwCZvlAe9RYv/5XlV2JCgewstYpJU4kyiPX3Z5BxrRwApZT9c6IjEfA2wVm1pipnzCAJe90QNoJ4fBc11EIPd8wTKHxOo2KLqVAGsZAAqAvLGTXZvXPqg=",headers="(request-target) (created) (expires) host date content-type content-length"'
    header.should.equal(expectedHeader)
  });
});
