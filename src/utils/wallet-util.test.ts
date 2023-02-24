/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { CRYPTO_ERROR, TEST_ERROR } from "../config/messages";
import { CRYPTO_ALGORITHMS, CRYPTO_CONFIG } from "../config/algorithm";
import { KeyType, PassKey, SecretKey, PrivateKey } from "../interfaces/key-interface";
import { WalletUtil } from "./wallet-util";

describe("Wallet Util Test Suite", () => {
  describe("generateKey()", () => {
    it("should generate a symmetric key", async () => {
      const testDomain = "test-domain";
      const secretKey: SecretKey = await WalletUtil.generateKey({ domain: testDomain });

      expect(secretKey.type).to.equal(KeyType.SecretKey);
      expect(secretKey.domain).to.equal(testDomain);
      expect(secretKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
    });
  });

  describe("generatePassKey()", () => {
    it("should generate a valid symmetric key from a passphrase", async () => {
      const passphrase = "password";
      const passKey: PassKey = await WalletUtil
        .generatePassKey({ passphrase: passphrase });

      expect(passKey.type).to.equal(KeyType.PassKey);
      expect(passKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
      expect(passKey.salt).to.exist;
    });

    it("should generate the same key from the same passphrase and salt", async () => {
      const passphrase = "password";
      const passKey1: PassKey = await WalletUtil.generatePassKey({ passphrase: passphrase });
      const passKey2: PassKey = await WalletUtil.generatePassKey({ passphrase: passphrase, salt: passKey1.salt });

      const rawPassKey1 = await WalletUtil.exportKey(passKey1);
      const rawPassKey2 = await WalletUtil.exportKey(passKey2);

      expect(rawPassKey1.salt).to.equal(rawPassKey2.salt);
      expect(rawPassKey1.crypto.k).to.deep.equal(rawPassKey2.crypto.k);
    });

    it("should throw an error if passphrase is not a string", async () => {
      const passphrase = 123;

      try {
        await WalletUtil.generatePassKey({ passphrase: passphrase as any });
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_PASSPHRASE);
      }
    });
  })

  describe("generatePrivateKey()", () => {
    it("should generate a private key", async () => {
      const privateKey = await WalletUtil.generatePrivateKey();

      expect(privateKey.type).to.equal(KeyType.PrivateKey);
      expect(privateKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.ASYMMETRIC.algorithm.name);
    });
  });

  describe("generatePublicKey()", () => {
    it("should generate a public key from a private key", async () => {
      const privateKey = await WalletUtil.generatePrivateKey();
      const publicKey = await WalletUtil.generatePublicKey({ privateKey });

      expect(publicKey.type).to.equal(KeyType.PublicKey);
      expect(publicKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.ASYMMETRIC.algorithm.name);
    });

    it("should throw an error if source key is not a valid ECDH key", async () => {
      const privateKey = "invalid-key" as any;

      try {
        await WalletUtil.generatePublicKey({ privateKey });
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_KEY);
      }
    });

    it("should throw an error if source key is not a private key", async () => {
      const privateKey = await WalletUtil.generatePrivateKey();
      const publicKey = await WalletUtil.generatePublicKey({ privateKey }) as any;

      try {
        await WalletUtil.generatePublicKey({ privateKey: publicKey });
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
      }
    });
  });

  describe("generateSharedKey()", () => {
    it("should generate a shared key from a private key in one key pair and a public key in another key pair", async () => {
      const alicePrivateKey = await WalletUtil.generatePrivateKey();

      const bobPrivateKey = await WalletUtil.generatePrivateKey();
      const bobPublicKey = await WalletUtil.generatePublicKey({ privateKey: bobPrivateKey });

      const sharedKey = await WalletUtil.generateSharedKey({
        privateKey: alicePrivateKey,
        publicKey: bobPublicKey
      });

      expect(sharedKey.type).to.equal(KeyType.SharedKey);
      expect(sharedKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
    });

    it("should generate the same shared key when using the same pair of key pairs", async () => {
      const alicePrivateKey = await WalletUtil.generatePrivateKey();
      const alicePublicKey = await WalletUtil.generatePublicKey({ privateKey: alicePrivateKey });

      const bobPrivateKey = await WalletUtil.generatePrivateKey();
      const bobPublicKey = await WalletUtil.generatePublicKey({ privateKey: bobPrivateKey });

      const sharedKey1 = await WalletUtil.generateSharedKey({
        privateKey: alicePrivateKey,
        publicKey: bobPublicKey
      });

      const sharedKey2 = await WalletUtil.generateSharedKey({
        privateKey: bobPrivateKey,
        publicKey: alicePublicKey
      });

      // same key type
      expect(sharedKey1.type).to.equal(sharedKey2.type).to.equal(KeyType.SharedKey);

      // same key algorithm
      expect(sharedKey1.crypto.algorithm.name).to.equal(sharedKey2.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);

      const rawSharedKey1 = await WalletUtil.exportKey(sharedKey1);
      const rawSharedKey2 = await WalletUtil.exportKey(sharedKey2);

      // same key
      expect(rawSharedKey1.crypto.k).to.equal(rawSharedKey2.crypto.k);


    });

    it("should be able to generate a shared key from a private key and a public key in the same key pair", async () => {
      const privateKey = await WalletUtil.generatePrivateKey();
      const publicKey = await WalletUtil.generatePublicKey({ privateKey });

      const sharedKey = await WalletUtil.generateSharedKey({ privateKey, publicKey });
      expect(sharedKey.type).to.equal(KeyType.SharedKey);
      expect(sharedKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
    });

    it("should throw an error if private/public key is not a valid ECDH key", async () => {
      const invalidPrivateKey = await WalletUtil.generateKey() as any;
      const invalidPublicKey = await WalletUtil.generateKey() as any;

      try {
        await WalletUtil.generateSharedKey({
          privateKey: invalidPrivateKey,
          publicKey: invalidPublicKey
        });
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
      }

      const validPrivateKey = await WalletUtil.generatePrivateKey();

      try {
        await WalletUtil.generateSharedKey({
          privateKey: validPrivateKey,
          publicKey: invalidPublicKey
        });
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_PUBLIC_KEY);
      }


    });

    it("should throw an error if the keys have the same type (private or public)", async () => {
      const privateKey1 = await WalletUtil.generatePrivateKey() as any;
      const privateKey2 = await WalletUtil.generatePrivateKey() as any;

      try {
        await WalletUtil.generateSharedKey({
          privateKey: privateKey1,
          publicKey: privateKey2
        });
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.IDENTICAL_KEY_TYPES);
      }
    });
  })

  describe("exportKey()", () => {
    it("should export SecretKey", async () => {
      const key = await WalletUtil.generateKey();
      const rawKey = await WalletUtil.exportKey(key);

      // check for key type
      expect(rawKey.type).to.equal(key.type).equal(KeyType.SecretKey);
      // check for jwk key type
      expect(rawKey.crypto.kty).to.equal(CRYPTO_ALGORITHMS.AES.jwk.kty);
      // check for jwk key algorithm
      expect(rawKey.crypto.alg).to.equal(CRYPTO_ALGORITHMS.AES.jwk.algo);
      // check for jwk key usage
      expect(rawKey.crypto.key_ops).to.deep.equal(key.crypto.usages);
      // check for key value
      expect(rawKey.crypto.k).to.exist;

      // check that domain was maintained
      expect(rawKey.domain).to.equal(key.domain);
    });

    it("should export PassKey", async () => {
      const passphrase = "test-passphrase";
      const passKey = await WalletUtil.generatePassKey({ passphrase });
      const rawPassKey = await WalletUtil.exportKey(passKey);

      // check for key type
      expect(rawPassKey.type).to.equal(passKey.type).equal(KeyType.PassKey);
      // check for jwk key type
      expect(rawPassKey.crypto.kty).to.equal(CRYPTO_ALGORITHMS.PBKDF2.jwk.kty);
      // check for jwk key algorithm
      expect(rawPassKey.crypto.alg).to.equal(CRYPTO_ALGORITHMS.PBKDF2.jwk.algo);
      // check for jwk key usage
      expect(rawPassKey.crypto.key_ops).to.deep.equal(passKey.crypto.usages);
      // check for key value
      expect(rawPassKey.crypto.k).to.exist;

      // should maintain hash algorithm
      expect(rawPassKey.hash).to.equal(passKey.hash);
      // should maintain salt
      expect(rawPassKey.salt).to.deep.equal(passKey.salt);
      // should maintain iterations
      expect(rawPassKey.iterations).to.equal(passKey.iterations);

      // check that domain was maintained
      expect(rawPassKey.domain).to.equal(passKey.domain);
    });

    it("should export PrivateKey", async () => {
      const privateKey = await WalletUtil.generatePrivateKey();
      const rawPrivateKey = await WalletUtil.exportKey(privateKey);

      // check for key type
      expect(rawPrivateKey.type).to.equal(privateKey.type).equal(KeyType.PrivateKey);
      // check for jwk key type
      expect(rawPrivateKey.crypto.kty).to.equal(CRYPTO_ALGORITHMS.ECDH.jwk.kty);
      // check for jwk ECDH curve algorithm
      expect(rawPrivateKey.crypto.crv).to.equal(CRYPTO_ALGORITHMS.ECDH.namedCurve);
      // check for jwk key usage
      expect(rawPrivateKey.crypto.key_ops).to.deep.equal(privateKey.crypto.usages);
      // check for key value
      expect(rawPrivateKey.crypto.d).to.exist;
      expect(rawPrivateKey.crypto.x).to.exist;
      expect(rawPrivateKey.crypto.y).to.exist;

      // check that domain was maintained
      expect(rawPrivateKey.domain).to.equal(privateKey.domain);

    });

    it("should export PublicKey", async () => {
      const privateKey = await WalletUtil.generatePrivateKey();
      const publicKey = await WalletUtil.generatePublicKey({ privateKey });
      const rawPublicKey = await WalletUtil.exportKey(publicKey);

      // check for key type
      expect(rawPublicKey.type).to.equal(publicKey.type).equal(KeyType.PublicKey);
      // check for jwk key type
      expect(rawPublicKey.crypto.kty).to.equal(CRYPTO_ALGORITHMS.ECDH.jwk.kty);
      // check for jwk ECDH curve algorithm
      expect(rawPublicKey.crypto.crv).to.equal(CRYPTO_ALGORITHMS.ECDH.namedCurve);
      // check for jwk key usage
      expect(rawPublicKey.crypto.key_ops).to.deep.equal(publicKey.crypto.usages);
      // check for key value
      expect(rawPublicKey.crypto.x).to.exist;
      expect(rawPublicKey.crypto.y).to.exist;

      // check that domain was maintained
      expect(rawPublicKey.domain).to.equal(publicKey.domain);
    });

    it("should throw an error if key is not valid", async () => {
      const key = "invalid-key" as any;

      try {
        await WalletUtil.exportKey(key);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR.COMMON.INVALID_KEY);
      }
    });
  });

  describe("importKey()", () => {
    it("should import SecretKey", async () => {
      const secretKey = await WalletUtil.generateKey();
      const rawKey = await WalletUtil.exportKey(secretKey);
      const importedKey = await WalletUtil.importKey(rawKey);

      expect(importedKey).to.deep.equal(secretKey);
    });

    it("should import PassKey", async () => {
      const passphrase = "test-passphrase";
      const passKey = await WalletUtil.generatePassKey({ passphrase: passphrase });
      const rawPassKey = await WalletUtil.exportKey(passKey);
      const importedKey = await WalletUtil.importKey(rawPassKey) as PassKey;

      expect(importedKey).to.deep.equal(passKey);
    });

    it("should import PrivateKey", async () => {
      const privateKey = await WalletUtil.generatePrivateKey();
      const publicKey = await WalletUtil.generatePublicKey({ privateKey });
      const rawPrivateKey = await WalletUtil.exportKey(privateKey);
      const importedKey = await WalletUtil.importKey(rawPrivateKey) as PrivateKey;

      // deep equal does not work for private keys
      expect(importedKey.type).to.equal(privateKey.type);
      expect(importedKey.domain).to.equal(privateKey.domain);

      const publicKeyFromImportedKey = await WalletUtil.generatePublicKey({ privateKey: importedKey });
      expect(publicKeyFromImportedKey).to.deep.equal(publicKey);


    });

    it("should import PublicKey", async () => {
      const privateKey = await WalletUtil.generatePrivateKey();
      const publicKey = await WalletUtil.generatePublicKey({ privateKey });
      const rawPublicKey = await WalletUtil.exportKey(publicKey);
      const importedKey = await WalletUtil.importKey(rawPublicKey);

      expect(importedKey).to.deep.equal(publicKey);
    });

    it("should throw an error if key is not a valid JSON Web Key", async () => {
      const key = "invalid-json-key" as any;

      try {
        await WalletUtil.importKey(key);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR.RAW.INVALID_KEY);
      }
    });
  });
});
