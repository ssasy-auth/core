/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { CRYPTO_ERROR, TEST_ERROR } from "../../src/config/messages";
import { CRYPTO_ALGORITHMS, CRYPTO_CONFIG } from "../../src/config/algorithm";
import { KeyType, Key, PassKey, SecretKey, PrivateKey } from "../../src/interfaces/key-interface";
import { CryptoMod, KeyHelper } from "../../src/modules/crypto-mod";
import { Ciphertext } from "../../src/interfaces/ciphertext-interface";

describe("CryptoMod Module Test Suite", () => {
  describe("Crypto", () => {
    describe("generateKey()", () => {
      it("should generate a symmetric key", async () => {
        const testDomain = "test-domain";
        const secretKey: SecretKey = await CryptoMod.generateKey({ domain: testDomain });
  
        expect(secretKey.type).to.equal(KeyType.SecretKey);
        expect(secretKey.domain).to.equal(testDomain);
        expect(secretKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
      });
    });
  
    describe("generatePassKey()", () => {
      it("should generate a valid symmetric key from a passphrase", async () => {
        const passphrase = "password";
        const passKey: PassKey = await CryptoMod
          .generatePassKey({ passphrase: passphrase });
  
        expect(passKey.type).to.equal(KeyType.PassKey);
        expect(passKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
        expect(passKey.salt).to.exist;
      });
  
      it("should generate the same key from the same passphrase and salt", async () => {
        const passphrase = "password";
        const passKey1: PassKey = await CryptoMod.generatePassKey({ passphrase: passphrase });
        const passKey2: PassKey = await CryptoMod.generatePassKey({ passphrase: passphrase, salt: passKey1.salt });
  
        const rawPassKey1 = await CryptoMod.exportKey(passKey1);
        const rawPassKey2 = await CryptoMod.exportKey(passKey2);
  
        expect(rawPassKey1.salt).to.equal(rawPassKey2.salt);
        expect(rawPassKey1.crypto.k).to.deep.equal(rawPassKey2.crypto.k);
      });
  
      it("should throw an error if passphrase is not a string", async () => {
        const passphrase = 123;
  
        try {
          await CryptoMod.generatePassKey({ passphrase: passphrase as any });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_PASSPHRASE);
        }
      });
    })
  
    describe("generatePrivateKey()", () => {
      it("should generate a private key", async () => {
        const privateKey = await CryptoMod.generatePrivateKey();
  
        expect(privateKey.type).to.equal(KeyType.PrivateKey);
        expect(privateKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.ASYMMETRIC.algorithm.name);
      });
    });
  
    describe("generatePublicKey()", () => {
      it("should generate a public key from a private key", async () => {
        const privateKey = await CryptoMod.generatePrivateKey();
        const publicKey = await CryptoMod.generatePublicKey({ privateKey });
  
        expect(publicKey.type).to.equal(KeyType.PublicKey);
        expect(publicKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.ASYMMETRIC.algorithm.name);
      });
  
      it("should throw an error if source key is not a valid ECDH key", async () => {
        const privateKey = "invalid-key" as any;
  
        try {
          await CryptoMod.generatePublicKey({ privateKey });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_KEY);
        }
      });
  
      it("should throw an error if source key is not a private key", async () => {
        const privateKey = await CryptoMod.generatePrivateKey();
        const publicKey = await CryptoMod.generatePublicKey({ privateKey }) as any;
  
        try {
          await CryptoMod.generatePublicKey({ privateKey: publicKey });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
        }
      });
    });
  
    describe("generateSharedKey()", () => {
      it("should generate a shared key from a private key in one key pair and a public key in another key pair", async () => {
        const alicePrivateKey = await CryptoMod.generatePrivateKey();
  
        const bobPrivateKey = await CryptoMod.generatePrivateKey();
        const bobPublicKey = await CryptoMod.generatePublicKey({ privateKey: bobPrivateKey });
  
        const sharedKey = await CryptoMod.generateSharedKey({
          privateKey: alicePrivateKey,
          publicKey: bobPublicKey
        });
  
        expect(sharedKey.type).to.equal(KeyType.SharedKey);
        expect(sharedKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
      });
  
      it("should generate the same shared key when using the same pair of key pairs", async () => {
        const alicePrivateKey = await CryptoMod.generatePrivateKey();
        const alicePublicKey = await CryptoMod.generatePublicKey({ privateKey: alicePrivateKey });
  
        const bobPrivateKey = await CryptoMod.generatePrivateKey();
        const bobPublicKey = await CryptoMod.generatePublicKey({ privateKey: bobPrivateKey });
  
        const sharedKey1 = await CryptoMod.generateSharedKey({
          privateKey: alicePrivateKey,
          publicKey: bobPublicKey
        });
  
        const sharedKey2 = await CryptoMod.generateSharedKey({
          privateKey: bobPrivateKey,
          publicKey: alicePublicKey
        });
  
        // same key type
        expect(sharedKey1.type).to.equal(sharedKey2.type).to.equal(KeyType.SharedKey);
  
        // same key algorithm
        expect(sharedKey1.crypto.algorithm.name).to.equal(sharedKey2.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
  
        const rawSharedKey1 = await CryptoMod.exportKey(sharedKey1);
        const rawSharedKey2 = await CryptoMod.exportKey(sharedKey2);
  
        // same key
        expect(rawSharedKey1.crypto.k).to.equal(rawSharedKey2.crypto.k);
  
  
      });
  
      it("should be able to generate a shared key from a private key and a public key in the same key pair", async () => {
        const privateKey = await CryptoMod.generatePrivateKey();
        const publicKey = await CryptoMod.generatePublicKey({ privateKey });
  
        const sharedKey = await CryptoMod.generateSharedKey({ privateKey, publicKey });
        expect(sharedKey.type).to.equal(KeyType.SharedKey);
        expect(sharedKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
      });
  
      it("should throw an error if private/public key is not a valid ECDH key", async () => {
        const invalidPrivateKey = await CryptoMod.generateKey() as any;
        const invalidPublicKey = await CryptoMod.generateKey() as any;
  
        try {
          await CryptoMod.generateSharedKey({
            privateKey: invalidPrivateKey,
            publicKey: invalidPublicKey
          });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
        }
  
        const validPrivateKey = await CryptoMod.generatePrivateKey();
  
        try {
          await CryptoMod.generateSharedKey({
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
        const privateKey1 = await CryptoMod.generatePrivateKey() as any;
        const privateKey2 = await CryptoMod.generatePrivateKey() as any;
  
        try {
          await CryptoMod.generateSharedKey({
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
  
    describe("encrypt()", () => {
      it("should encrypt a plaintext with a SecretKey and return a Ciphertext", async () => {
        const key = await CryptoMod.generateKey();
        const plaintext = "hello world";
        const ciphertext = await CryptoMod.encrypt(key, plaintext);
  
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
        const passKey = await CryptoMod.generatePassKey({ passphrase: passphrase });
        const plaintext = "hello world";
  
        const ciphertext = await CryptoMod.encrypt(passKey, plaintext);
  
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
        const senderPrivateKey = await CryptoMod.generatePrivateKey();
        const receiverPrivateKey = await CryptoMod.generatePrivateKey();
        const receiverPublicKey = await CryptoMod.generatePublicKey({ privateKey: receiverPrivateKey });
  
        const sharedKey = await CryptoMod.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });
  
        const plaintext = "hello world";
        const ciphertext = await CryptoMod.encrypt(sharedKey, plaintext);
  
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
  
      it("should add sender and recipient public keys to ciphertext when provided")
  
      it("should throw an error if key is not a valid AES", async () => {
        const key = "invalid-key" as any;
        const plaintext = "hello world";
  
        try {
          await CryptoMod.encrypt(key, plaintext);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_KEY);
        }
      });
  
      it("should throw an error if plaintext is not a string", async () => {
        const passphrase = "password";
        const passKey = await CryptoMod.generatePassKey({ passphrase: passphrase });
  
        const plaintext = 123 as any;
  
        try {
          await CryptoMod.encrypt(passKey, plaintext);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_PLAINTEXT);
        }
      });
    });
  
    describe("decrypt()", () => {
      it("should decrypt SecretKey's Ciphertext", async () => {
        const key = await CryptoMod.generateKey();
        const plaintext = "hello world";
        const ciphertext = await CryptoMod.encrypt(key, plaintext);
        const decryptedPlaintext = await CryptoMod.decrypt(key, ciphertext);
  
        expect(decryptedPlaintext).to.equal(plaintext);
      });
  
      it("should decrypt PassKey's Ciphertext", async () => {
        const passphrase = "password";
        const message = "hello world";
  
        const encryptPassKey = await CryptoMod.generatePassKey({ passphrase: passphrase });
        const ciphertext = await CryptoMod.encrypt(encryptPassKey, message);
        const decryptPassKey = await CryptoMod.generatePassKey({ passphrase: passphrase, salt: encryptPassKey.salt });
  
        const plaintext = await CryptoMod.decrypt(decryptPassKey, ciphertext);
  
        expect(message).to.equal(plaintext);
      });
  
      it("should decrypt SharedKey's Ciphertext", async () => {
        const senderPrivateKey = await CryptoMod.generatePrivateKey();
        const senderPublicKey = await CryptoMod.generatePublicKey({ privateKey: senderPrivateKey });
        const receiverPrivateKey = await CryptoMod.generatePrivateKey();
        const receiverPublicKey = await CryptoMod.generatePublicKey({ privateKey: receiverPrivateKey });
  
        const senderSharedKey = await CryptoMod.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });
        const senderMessage = "hello world from sender";
        const senderCiphertext = await CryptoMod.encrypt(senderSharedKey, senderMessage);
  
        const receiverSharedKey = await CryptoMod.generateSharedKey({ privateKey: receiverPrivateKey, publicKey: senderPublicKey });
        const receiverMessage = "hello world from receiver";
        const receiverCiphertext = await CryptoMod.encrypt(receiverSharedKey, receiverMessage);
  
        // reciver should be able to decrypt sender's message
        const decryptedSenderMessage = await CryptoMod.decrypt(receiverSharedKey, senderCiphertext);
        expect(decryptedSenderMessage).to.equal(senderMessage);
  
        // sender should be able to decrypt receiver's message
        const decryptedReceiverMessage = await CryptoMod.decrypt(senderSharedKey, receiverCiphertext);
        expect(decryptedReceiverMessage).to.equal(receiverMessage);
      });
  
      it("should throw error if key was not used to encrypt ciphertext", async () => {
        const key = await CryptoMod.generateKey();
        const invalidKey = await CryptoMod.generateKey();
  
        const plaintext = "hello world";
        const ciphertext = await CryptoMod.encrypt(key, plaintext);
  
  
        try {
          await CryptoMod.decrypt(invalidKey, ciphertext);
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
          await CryptoMod.decrypt(key, cipherText);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_KEY);
        }
      });
  
      it("should throw an error if ciphertext is not valid", async () => {
        const key = await CryptoMod.generateKey();
        const cipherText: Ciphertext = "invalid-ciphertext" as any;
  
        try {
          await CryptoMod.decrypt(key, cipherText);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.SYMMETRIC.INVALID_CIPHERTEXT);
        }
      });
    });
  
    describe("hash()", () => {
      it("should hash a string", async () => {
        const string = "hello world";
        const hash = await CryptoMod.hash(string);
  
        expect(hash).to.be.a("string");
      })
  
      it("should create the same hash for the same string", async () => {
        const string = "hello world";
        const hash1 = await CryptoMod.hash(string);
        const hash2 = await CryptoMod.hash(string);
  
        expect(hash1).to.equal(hash2);
      })
  
      it("should create a different hash for a different string", async () => {
        const string1 = "hello world";
        const string2 = "hello world!";
        const hash1 = await CryptoMod.hash(string1);
        const hash2 = await CryptoMod.hash(string2);
  
        expect(hash1).to.not.equal(hash2);
      })
  
      it("should throw an error if string is not a string", async () => {
        const string = 123 as any;
  
        try {
          await CryptoMod.hash(string);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.HASH.INVALID_STRING);
        }
      })
    })
  
    describe("exportKey()", () => {
      it("should export SecretKey", async () => {
        const key = await CryptoMod.generateKey();
        const rawKey = await CryptoMod.exportKey(key);
  
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
        const passKey = await CryptoMod.generatePassKey({ passphrase });
        const rawPassKey = await CryptoMod.exportKey(passKey);
  
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
        const privateKey = await CryptoMod.generatePrivateKey();
        const rawPrivateKey = await CryptoMod.exportKey(privateKey);
  
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
        const privateKey = await CryptoMod.generatePrivateKey();
        const publicKey = await CryptoMod.generatePublicKey({ privateKey });
        const rawPublicKey = await CryptoMod.exportKey(publicKey);
  
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
          await CryptoMod.exportKey(key);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.COMMON.INVALID_KEY);
        }
      });
    });
  
    describe("importKey()", () => {
      it("should import SecretKey", async () => {
        const secretKey = await CryptoMod.generateKey();
        const rawKey = await CryptoMod.exportKey(secretKey);
        const importedKey = await CryptoMod.importKey(rawKey);
  
        expect(importedKey).to.deep.equal(secretKey);
      });
  
      it("should import PassKey", async () => {
        const passphrase = "test-passphrase";
        const passKey = await CryptoMod.generatePassKey({ passphrase: passphrase });
        const rawPassKey = await CryptoMod.exportKey(passKey);
        const importedKey = await CryptoMod.importKey(rawPassKey) as PassKey;
  
        expect(importedKey).to.deep.equal(passKey);
      });
  
      it("should import PrivateKey", async () => {
        const privateKey = await CryptoMod.generatePrivateKey();
        const publicKey = await CryptoMod.generatePublicKey({ privateKey });
        const rawPrivateKey = await CryptoMod.exportKey(privateKey);
        const importedKey = await CryptoMod.importKey(rawPrivateKey) as PrivateKey;
  
        // deep equal does not work for private keys
        expect(importedKey.type).to.equal(privateKey.type);
        expect(importedKey.domain).to.equal(privateKey.domain);
  
        const publicKeyFromImportedKey = await CryptoMod.generatePublicKey({ privateKey: importedKey });
        expect(publicKeyFromImportedKey).to.deep.equal(publicKey);
  
  
      });
  
      it("should import PublicKey", async () => {
        const privateKey = await CryptoMod.generatePrivateKey();
        const publicKey = await CryptoMod.generatePublicKey({ privateKey });
        const rawPublicKey = await CryptoMod.exportKey(publicKey);
        const importedKey = await CryptoMod.importKey(rawPublicKey);
  
        expect(importedKey).to.deep.equal(publicKey);
      });
  
      it("should throw an error if key is not a valid JSON Web Key", async () => {
        const key = "invalid-json-key" as any;
  
        try {
          await CryptoMod.importKey(key);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.RAW.INVALID_KEY);
        }
      });
    });
  
    describe("isSameKey()", () => {
      it("should return true if two keys are the same", async () => {
        let isSame: boolean;
  
        const secretKey = await CryptoMod.generateKey();
        isSame = await CryptoMod.isSameKey(secretKey, secretKey);
        expect(isSame).to.be.true;
        
        const passKey = await CryptoMod.generatePassKey({ passphrase: "test-passphrase" });
        isSame = await CryptoMod.isSameKey(passKey, passKey);
        expect(isSame).to.be.true;
        
        const privateKey = await CryptoMod.generatePrivateKey();
        isSame = await CryptoMod.isSameKey(privateKey, privateKey);
        expect(isSame).to.be.true;
        
        const publicKey = await CryptoMod.generatePublicKey({ privateKey });
        isSame = await CryptoMod.isSameKey(publicKey, publicKey);
        expect(isSame).to.be.true;
      })
  
      it("should return false if two keys are not the same", async () => {
        let isSame: boolean;
        const secretKey = await CryptoMod.generateKey();
        const passKey = await CryptoMod.generatePassKey({ passphrase: "test-passphrase" });
        const privateKey = await CryptoMod.generatePrivateKey();
        const publicKey = await CryptoMod.generatePublicKey({ privateKey });
  
        isSame = await CryptoMod.isSameKey(secretKey, passKey);
        expect(isSame).to.be.false;
        
        isSame = await CryptoMod.isSameKey(privateKey, publicKey);
        expect(isSame).to.be.false;
      })
  
      it("should throw error if keys are not valid (not valid = is a raw key or is not a key)", async () => {
        const secretKey = await CryptoMod.generateKey();
        const rawSecretKey = await CryptoMod.exportKey(secretKey);
        
        try {
          await CryptoMod.isSameKey(rawSecretKey as any, secretKey)
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.COMMON.KEY_NOT_SUPPORTED);
        }
  
        try {
          await CryptoMod.isSameKey("invalid" as any, secretKey)
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR.COMMON.INVALID_KEY);
        }
      })
    });
  })

  describe("Key Helper", () => {
    const { isRawKey, isKey, isSymmetricKey, isAsymmetricKey } = KeyHelper

    describe("isRawKey()", () => {
      it("should return true for a valid raw key", async () => {
        const key = await CryptoMod.generateKey()
        const rawKey = await CryptoMod.exportKey(key) as Key;

        expect(isRawKey(rawKey)).to.be.true;
      })

      it("should return false for an invalid raw key", async () => {
        const key = await CryptoMod.generateKey()
        expect(isRawKey(key)).to.be.false;

        const passKey = await CryptoMod.generatePassKey({ passphrase: "test" })
        expect(isRawKey(passKey)).to.be.false;

        const privateKey = await CryptoMod.generatePrivateKey()
        expect(isRawKey(privateKey)).to.be.false;

        const publicKey = await CryptoMod.generatePublicKey({ privateKey })
        expect(isRawKey(publicKey)).to.be.false;

      })
    })

    describe("isKey()", () => {
      it("should return true for a valid key", async () => {
        const key = await CryptoMod.generateKey()
        expect(isKey(key)).to.be.true;

        const passKey = await CryptoMod.generatePassKey({ passphrase: "test" })
        expect(isKey(passKey)).to.be.true;

        const privateKey = await CryptoMod.generatePrivateKey()
        expect(isKey(privateKey)).to.be.true;

        const publicKey = await CryptoMod.generatePublicKey({ privateKey })
        expect(isKey(publicKey)).to.be.true;

        const extraPrivateKey = await CryptoMod.generatePrivateKey()
        const sharedKey = await CryptoMod.generateSharedKey({ privateKey: extraPrivateKey, publicKey })
        expect(isKey(sharedKey)).to.be.true;
      })

      it("should return false for an invalid key", async () => {
        const { crypto } = await CryptoMod.generateKey();
        expect(isKey(crypto as any)).to.be.false;
      })
    })

    describe("isSymmetricKey()", () => {
      it("should return true for a valid symmetric key", async () => {
        const key = await CryptoMod.generateKey()
        expect(isSymmetricKey(key)).to.be.true;

        const passKey = await CryptoMod.generatePassKey({ passphrase: "test" })
        expect(isSymmetricKey(passKey)).to.be.true;

        const privateKey = await CryptoMod.generatePrivateKey()
        const publicKey = await CryptoMod.generatePublicKey({ privateKey })
        const otherPrivateKey = await CryptoMod.generatePrivateKey()
        const sharedKey = await CryptoMod.generateSharedKey({ privateKey: otherPrivateKey, publicKey })
        expect(isSymmetricKey(sharedKey)).to.be.true;
      })

      it("should return false for an invalid symmetric key", async () => {
        const privateKey = await CryptoMod.generatePrivateKey()
        expect(isSymmetricKey(privateKey)).to.be.false;

        const publicKey = await CryptoMod.generatePublicKey({ privateKey })
        expect(isSymmetricKey(publicKey)).to.be.false;
      })
    })

    describe("isAsymmetricKey()", () => {
      it("should return true for a valid asymmetric key", async () => {
        const privateKey = await CryptoMod.generatePrivateKey()
        expect(isAsymmetricKey(privateKey)).to.be.true;

        const publicKey = await CryptoMod.generatePublicKey({ privateKey })
        expect(isAsymmetricKey(publicKey)).to.be.true;
      })

      it("should return false for an invalid asymmetric key", async () => {
        const key = await CryptoMod.generateKey()
        expect(isAsymmetricKey(key)).to.be.false;

        const passKey = await CryptoMod.generatePassKey({ passphrase: "test" })
        expect(isAsymmetricKey(passKey)).to.be.false;

        const privateKey = await CryptoMod.generatePrivateKey()
        const publicKey = await CryptoMod.generatePublicKey({ privateKey })
        const otherPrivateKey = await CryptoMod.generatePrivateKey()
        const sharedKey = await CryptoMod.generateSharedKey({ privateKey: otherPrivateKey, publicKey })
        expect(isAsymmetricKey(sharedKey)).to.be.false;
      })
    })
  })
});