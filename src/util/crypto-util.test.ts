/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { CRYPTO_ERROR, TEST_ERROR } from "../config/messages";
import { CRYPTO_ALGORITHMS } from "../config/algorithm";
import { Ciphertext } from "../interfaces/crypto-interface";
import { KeyType, PassKey, SecretKey, PrivateKey } from "../interfaces/key-interface";
import { CRYPTO_CONFIG, CryptoUtil } from "./crypto-util"

describe("Crypto Util Test Suite", () => {
  describe("=> Key Generation", () => {
    describe("generateKey()", () => {
      it("should generate a symmetric key", async () => {
        const testDomain = "test-domain";
        const secretKey: SecretKey = await CryptoUtil.generateKey({ domain: testDomain });

        expect(secretKey.type).to.equal(KeyType.SecretKey);
        expect(secretKey.domain).to.equal(testDomain);
        expect(secretKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
      });
    });

    describe("generatePassKey()", () => {
      it("should generate a valid symmetric key from a passphrase", async () => {
        const passphrase = "password";
        const passKey: PassKey = await CryptoUtil
          .generatePassKey({ passphrase: passphrase });

        expect(passKey.type).to.equal(KeyType.PassKey);
        expect(passKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
        expect(passKey.salt).to.exist;
      });

      it("should generate the same key from the same passphrase and salt", async () => {
        const passphrase = "password";
        const passKey1: PassKey = await CryptoUtil.generatePassKey({ passphrase: passphrase });
        const passKey2: PassKey = await CryptoUtil.generatePassKey({ passphrase: passphrase, salt: passKey1.salt });

        const rawPassKey1 = await CryptoUtil.exportKey(passKey1);
        const rawPassKey2 = await CryptoUtil.exportKey(passKey2);

        expect(rawPassKey1.salt).to.equal(rawPassKey2.salt);
        expect(rawPassKey1.crypto.k).to.deep.equal(rawPassKey2.crypto.k);
      });

      it("should throw an error if passphrase is not a string", async () => {
        const passphrase = 123;

        try {
          await CryptoUtil.generatePassKey({ passphrase: passphrase as any });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_PASSPHRASE);
        }
      });
    })

    describe("generatePrivateKey()", () => {
      it("should generate a private key", async () => {
        const privateKey = await CryptoUtil.generatePrivateKey();

        expect(privateKey.type).to.equal(KeyType.PrivateKey);
        expect(privateKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.ASYMMETRIC.algorithm.name);
      });
    });

    describe("generatePublicKey()", () => {
      it("should generate a public key from a private key", async () => {
        const privateKey = await CryptoUtil.generatePrivateKey();
        const publicKey = await CryptoUtil.generatePublicKey({ privateKey });

        expect(publicKey.type).to.equal(KeyType.PublicKey);
        expect(publicKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.ASYMMETRIC.algorithm.name);
      });

      it("should throw an error if source key is not a valid ECDH key", async () => {
        const privateKey = "invalid-key" as any;

        try {
          await CryptoUtil.generatePublicKey({ privateKey });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_KEY);
        }
      });

      it("should throw an error if source key is not a private key", async () => {
        const privateKey = await CryptoUtil.generatePrivateKey();
        const publicKey = await CryptoUtil.generatePublicKey({ privateKey }) as any;

        try {
          await CryptoUtil.generatePublicKey({ privateKey: publicKey });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
        }
      });
    });

    describe("generateSharedKey()", () => {
      it("should generate a shared key from a private key in one key pair and a public key in another key pair", async () => {
        const alicePrivateKey = await CryptoUtil.generatePrivateKey();

        const bobPrivateKey = await CryptoUtil.generatePrivateKey();
        const bobPublicKey = await CryptoUtil.generatePublicKey({ privateKey: bobPrivateKey });

        const sharedKey = await CryptoUtil.generateSharedKey({
          privateKey: alicePrivateKey,
          publicKey: bobPublicKey
        });

        expect(sharedKey.type).to.equal(KeyType.SharedKey);
        expect(sharedKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
      });

      it("should generate the same shared key when using the same pair of key pairs", async () => {
        const alicePrivateKey = await CryptoUtil.generatePrivateKey();
        const alicePublicKey = await CryptoUtil.generatePublicKey({ privateKey: alicePrivateKey });

        const bobPrivateKey = await CryptoUtil.generatePrivateKey();
        const bobPublicKey = await CryptoUtil.generatePublicKey({ privateKey: bobPrivateKey });

        const sharedKey1 = await CryptoUtil.generateSharedKey({
          privateKey: alicePrivateKey,
          publicKey: bobPublicKey
        });

        const sharedKey2 = await CryptoUtil.generateSharedKey({
          privateKey: bobPrivateKey,
          publicKey: alicePublicKey
        });

        // same key type
        expect(sharedKey1.type).to.equal(sharedKey2.type).to.equal(KeyType.SharedKey);

        // same key algorithm
        expect(sharedKey1.crypto.algorithm.name).to.equal(sharedKey2.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);

        const rawSharedKey1 = await CryptoUtil.exportKey(sharedKey1);
        const rawSharedKey2 = await CryptoUtil.exportKey(sharedKey2);

        // same key
        expect(rawSharedKey1.crypto.k).to.equal(rawSharedKey2.crypto.k);


      });

      it("should throw an error if private/public key is not a valid ECDH key", async () => {
        const invalidPrivateKey = await CryptoUtil.generateKey() as any;
        const invalidPublicKey = await CryptoUtil.generateKey() as any;

        try {
          await CryptoUtil.generateSharedKey({
            privateKey: invalidPrivateKey,
            publicKey: invalidPublicKey
          });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
        }

        const validPrivateKey = await CryptoUtil.generatePrivateKey();

        try {
          await CryptoUtil.generateSharedKey({
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
        const privateKey1 = await CryptoUtil.generatePrivateKey() as any;
        const privateKey2 = await CryptoUtil.generatePrivateKey() as any;

        try {
          await CryptoUtil.generateSharedKey({
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
        const key = await CryptoUtil.generateKey();
        const rawKey = await CryptoUtil.exportKey(key);

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
        const passKey = await CryptoUtil.generatePassKey({ passphrase });
        const rawPassKey = await CryptoUtil.exportKey(passKey);

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
        const privateKey = await CryptoUtil.generatePrivateKey();
        const rawPrivateKey = await CryptoUtil.exportKey(privateKey);

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
        const privateKey = await CryptoUtil.generatePrivateKey();
        const publicKey = await CryptoUtil.generatePublicKey({ privateKey });
        const rawPublicKey = await CryptoUtil.exportKey(publicKey);

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
          await CryptoUtil.exportKey(key);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.COMMON.INVALID_KEY);
        }
      });
    });

    describe("importKey()", () => {
      it("should import SecretKey", async () => {
        const secretKey = await CryptoUtil.generateKey();
        const rawKey = await CryptoUtil.exportKey(secretKey);
        const importedKey = await CryptoUtil.importKey(rawKey);

        expect(importedKey).to.deep.equal(secretKey);
      });

      it("should import PassKey", async () => {
        const passphrase = "test-passphrase";
        const passKey = await CryptoUtil.generatePassKey({ passphrase: passphrase });
        const rawPassKey = await CryptoUtil.exportKey(passKey);
        const importedKey = await CryptoUtil.importKey(rawPassKey) as PassKey;

        expect(importedKey).to.deep.equal(passKey);
      });

      it("should import PrivateKey", async () => {
        const privateKey = await CryptoUtil.generatePrivateKey();
        const publicKey = await CryptoUtil.generatePublicKey({ privateKey });
        const rawPrivateKey = await CryptoUtil.exportKey(privateKey);
        const importedKey = await CryptoUtil.importKey(rawPrivateKey) as PrivateKey;

        // deep equal does not work for private keys
        expect(importedKey.type).to.equal(privateKey.type);
        expect(importedKey.domain).to.equal(privateKey.domain);

        const publicKeyFromImportedKey = await CryptoUtil.generatePublicKey({ privateKey: importedKey });
        expect(publicKeyFromImportedKey).to.deep.equal(publicKey);


      });

      it("should import PublicKey", async () => {
        const privateKey = await CryptoUtil.generatePrivateKey();
        const publicKey = await CryptoUtil.generatePublicKey({ privateKey });
        const rawPublicKey = await CryptoUtil.exportKey(publicKey);
        const importedKey = await CryptoUtil.importKey(rawPublicKey);

        expect(importedKey).to.deep.equal(publicKey);
      });

      it("should throw an error if key is not a valid JSON Web Key", async () => {
        const key = "invalid-json-key" as any;

        try {
          await CryptoUtil.importKey(key);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.RAW.INVALID_KEY);
        }
      });
    });
  });

  describe("=> Symmetric Operations", () => {
    

    describe("encrypt()", () => {
      it("should encrypt a plaintext with a SecretKey and return a Ciphertext", async () => {
        const key = await CryptoUtil.generateKey();
        const plaintext = "hello world";
        const ciphertext = await CryptoUtil.encrypt(key, plaintext);

        // ciphertext should not be the same as plaintext
        expect(ciphertext.data)
          .to.not.equal(plaintext)
          .and.to.not.include(plaintext);
        // ciphertext should be a base64 string
        expect(ciphertext.data).to.match(/^[a-zA-Z0-9+/]+={0,2}$/);
        // ciphertext should have a salt
        expect(ciphertext.salt).to.exist;
        // salt should be a uint8array
        expect(ciphertext.salt).to.be.instanceOf(Uint8Array);
      });

      it("should encrypt a plaintext with a PassKey and return a Ciphertext", async () => {
        const passphrase = "password";
        const passKey = await CryptoUtil.generatePassKey({ passphrase: passphrase });
        const plaintext = "hello world";

        const ciphertext = await CryptoUtil.encrypt(passKey, plaintext);

        // ciphertext should not be the same as plaintext
        expect(ciphertext.data)
          .to.not.equal(plaintext)
          .and.to.not.include(plaintext);
        // ciphertext should be a base64 string
        expect(ciphertext.data).to.match(/^[a-zA-Z0-9+/]+={0,2}$/);
        // ciphertext should have a salt
        expect(ciphertext.salt).to.exist;
        // salt should be a uint8array
        expect(ciphertext.salt).to.be.instanceOf(Uint8Array);
      });

      it("should encrypt a plaintext with a SharedKey and return a Ciphertext", async () => {
        const senderPrivateKey = await CryptoUtil.generatePrivateKey();
        const receiverPrivateKey = await CryptoUtil.generatePrivateKey();
        const receiverPublicKey = await CryptoUtil.generatePublicKey({ privateKey: receiverPrivateKey });
        
        const sharedKey = await CryptoUtil.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });
        
        const plaintext = "hello world";
        const ciphertext = await CryptoUtil.encrypt(sharedKey, plaintext);

        // ciphertext should not be the same as plaintext
        expect(ciphertext.data)
          .to.not.equal(plaintext)
          .and.to.not.include(plaintext);
        // ciphertext should be a base64 string
        expect(ciphertext.data).to.match(/^[a-zA-Z0-9+/]+={0,2}$/);
        // ciphertext should have a salt
        expect(ciphertext.salt).to.exist;
        // salt should be a uint8array
        expect(ciphertext.salt).to.be.instanceOf(Uint8Array);
      });

      it("should throw an error if key is not a valid AES", async () => {
        const key = "invalid-key" as any;
        const plaintext = "hello world";

        try {
          await CryptoUtil.encrypt(key, plaintext);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_KEY);
        }
      });

      it("should throw an error if plaintext is not a string", async () => {
        const passphrase = "password";
        const passKey = await CryptoUtil.generatePassKey({ passphrase: passphrase });

        const plaintext = 123 as any;

        try {
          await CryptoUtil.encrypt(passKey, plaintext);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_PLAINTEXT);
        }
      });
    });

    describe("decrypt()", () => {
      it("should decrypt SecretKey's Ciphertext", async () => {
        const key = await CryptoUtil.generateKey();
        const plaintext = "hello world";
        const ciphertext = await CryptoUtil.encrypt(key, plaintext);
        const decryptedPlaintext = await CryptoUtil.decrypt(key, ciphertext);

        expect(decryptedPlaintext).to.equal(plaintext);
      });

      it("should decrypt PassKey's Ciphertext", async () => {
        const passphrase = "password";
        const message = "hello world";

        const encryptPassKey = await CryptoUtil.generatePassKey({ passphrase: passphrase });
        const ciphertext = await CryptoUtil.encrypt(encryptPassKey, message);
        const decryptPassKey = await CryptoUtil.generatePassKey({ passphrase: passphrase, salt: encryptPassKey.salt });

        const plaintext = await CryptoUtil.decrypt(decryptPassKey, ciphertext);

        expect(message).to.equal(plaintext);
      });

      it("should decrypt SharedKey's Ciphertext", async () => {
        const senderPrivateKey = await CryptoUtil.generatePrivateKey();
        const senderPublicKey = await CryptoUtil.generatePublicKey({ privateKey: senderPrivateKey });
        const receiverPrivateKey = await CryptoUtil.generatePrivateKey();
        const receiverPublicKey = await CryptoUtil.generatePublicKey({ privateKey: receiverPrivateKey });

        const senderSharedKey = await CryptoUtil.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });
        const senderMessage = "hello world from sender";
        const senderCiphertext = await CryptoUtil.encrypt(senderSharedKey, senderMessage);
        
        const receiverSharedKey = await CryptoUtil.generateSharedKey({ privateKey: receiverPrivateKey, publicKey: senderPublicKey });
        const receiverMessage = "hello world from receiver";
        const receiverCiphertext = await CryptoUtil.encrypt(receiverSharedKey, receiverMessage);

        // reciver should be able to decrypt sender's message
        const decryptedSenderMessage = await CryptoUtil.decrypt(receiverSharedKey, senderCiphertext);
        expect(decryptedSenderMessage).to.equal(senderMessage);

        // sender should be able to decrypt receiver's message
        const decryptedReceiverMessage = await CryptoUtil.decrypt(senderSharedKey, receiverCiphertext);
        expect(decryptedReceiverMessage).to.equal(receiverMessage);
      });
      
      it("should throw error if key was not used to encrypt ciphertext", async () => {
        const key = await CryptoUtil.generateKey();
        const invalidKey = await CryptoUtil.generateKey();

        const plaintext = "hello world";
        const ciphertext = await CryptoUtil.encrypt(key, plaintext);
        

        try {
          await CryptoUtil.decrypt(invalidKey, ciphertext);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.WRONG_KEY);
        }
      });

      it("should throw an error if key is not a valid AES key", async () => {
        const key = "invalid-key" as any;
        const cipherText: Ciphertext = {
          data: "hello world",
          // uint8array
          salt: new Uint8Array([ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 ])
        };

        try {
          await CryptoUtil.decrypt(key, cipherText);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_KEY);
        }
      });

      it("should throw an error if ciphertext is not valid", async () => {
        const key = await CryptoUtil.generateKey();
        const cipherText: Ciphertext = "invalid-ciphertext" as any;

        try {
          await CryptoUtil.decrypt(key, cipherText);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_CIPHERTEXT);
        }
      });
    });
  });

})