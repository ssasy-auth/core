/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { TEST_ERROR } from "../config";
import { KeyModule } from "../../src/modules/key-mod";
import { CryptoModule, CRYPTO_ERROR_MESSAGE } from "../../src/modules/crypto-mod";
import type { Ciphertext } from "../../src/interfaces/ciphertext-interface";
import type { PassKey, SecretKey } from "../../src/interfaces/key-interface";

describe("CryptoModule Test Suite", () => {
  let validKey: SecretKey;
  let validPassKey: PassKey;

  const validPassphrase = "password";
  const validPlaintext = "hello world";

  before(async () => {
    validKey = await KeyModule.generateKey();
    validPassKey = await KeyModule.generatePassKey({ passphrase: validPassphrase });
  });

  describe("encrypt()", () => {
    it("should encrypt a plaintext with a SecretKey and return a Ciphertext", async () => {
      const ciphertext = await CryptoModule.encrypt(validKey, validPlaintext);

      // ciphertext should not be the same as plaintext
      expect(ciphertext.data)
        .to.not.equal(validPlaintext)
        .and.to.not.include(validPlaintext);
      // ciphertext should be a base64 string
      expect(ciphertext.data).to.match(/^[a-zA-Z0-9+/]+={0,2}$/);
      // ciphertext should have a salt
      expect(ciphertext.iv).to.exist;
      // salt should be a uint8array
      expect(ciphertext.iv).to.be.instanceOf(Uint8Array);
    });

    it("should encrypt a plaintext with a PassKey and return a Ciphertext", async () => {
      
      const ciphertext = await CryptoModule.encrypt(validPassKey, validPlaintext);

      // ciphertext should not be the same as plaintext
      expect(ciphertext.data)
        .to.not.equal(validPlaintext)
        .and.to.not.include(validPlaintext);
      // ciphertext should be a base64 string
      expect(ciphertext.data).to.match(/^[a-zA-Z0-9+/]+={0,2}$/);
      // ciphertext should have a salt
      expect(ciphertext.iv).to.exist;
      // salt should be a uint8array
      expect(ciphertext.iv).to.be.instanceOf(Uint8Array);
    });

    it("should encrypt a plaintext with a passphrase string and return a Ciphertext with passkey salt", async () => {
      const ciphertext = await CryptoModule.encrypt(validPassphrase, validPlaintext);

      // ciphertext should not be the same as plaintext
      expect(ciphertext.data)
        .to.not.equal(validPlaintext)
        .and.to.not.include(validPlaintext);
      // ciphertext should be a base64 string
      expect(ciphertext.data).to.match(/^[a-zA-Z0-9+/]+={0,2}$/);
      // ciphertext should have a iv
      expect(ciphertext.iv).to.exist;
      // iv should be a uint8array
      expect(ciphertext.iv).to.be.instanceOf(Uint8Array);
      // ciphertext should have a salt
      expect(ciphertext.salt).to.exist;
      // salt should be a uint8array
      expect(ciphertext.salt).to.be.instanceOf(Uint8Array);
    });

    it("should encrypt a plaintext with a SharedKey and return a Ciphertext", async () => {
      const senderPrivateKey = await KeyModule.generatePrivateKey();
      const receiverPrivateKey = await KeyModule.generatePrivateKey();
      const receiverPublicKey = await KeyModule.generatePublicKey({ privateKey: receiverPrivateKey });
      const sharedKey = await KeyModule.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });

      const ciphertext = await CryptoModule.encrypt(sharedKey, validPlaintext);

      // ciphertext should not be the same as plaintext
      expect(ciphertext.data)
        .to.not.equal(validPlaintext)
        .and.to.not.include(validPlaintext);
      // ciphertext should be a base64 string
      expect(ciphertext.data).to.match(/^[a-zA-Z0-9+/]+={0,2}$/);
      // ciphertext should have a salt
      expect(ciphertext.iv).to.exist;
      // salt should be a uint8array
      expect(ciphertext.iv).to.be.instanceOf(Uint8Array);
    });

    it("should add sender and recipient public keys to ciphertext when provided", async () => {
      const senderPrivateKey = await KeyModule.generatePrivateKey();
      const senderPublicKey = await KeyModule.generatePublicKey({ privateKey: senderPrivateKey });
      const receiverPrivateKey = await KeyModule.generatePrivateKey();
      const receiverPublicKey = await KeyModule.generatePublicKey({ privateKey: receiverPrivateKey });
      const sharedKey = await KeyModule.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });

      const ciphertext = await CryptoModule.encrypt(sharedKey, validPlaintext, senderPublicKey, receiverPublicKey);

      expect(ciphertext.sender).to.deep.equal(senderPublicKey);
      expect(ciphertext.recipient).to.deep.equal(receiverPublicKey);
    })

    it("should throw an error if key is not a valid symmetric key or string", async () => {
      const invalidKey = KeyModule.generatePrivateKey() as any;

      try {
        await CryptoModule.encrypt(invalidKey, validPlaintext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_SYMMETRIC_KEY);
      }
    });

    it("should throw an error if plaintext is not a string", async () => {
      const invalidPlaintext = 123 as any;

      try {
        await CryptoModule.encrypt(validPassKey, invalidPlaintext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_PLAINTEXT);
      }
    });
  });

  describe("decrypt()", () => {
    it("should decrypt SecretKey's Ciphertext", async () => {
      const ciphertext = await CryptoModule.encrypt(validKey, validPlaintext);
      const decryptedPlaintext = await CryptoModule.decrypt(validKey, ciphertext);

      expect(decryptedPlaintext).to.equal(validPlaintext);
    });

    it("should decrypt PassKey's Ciphertext", async () => {
      const validPassKeyCopy = await KeyModule.generatePassKey({ passphrase: validPassphrase, salt: validPassKey.salt });
      const ciphertext = await CryptoModule.encrypt(validPassKey, validPlaintext);

      const plaintext = await CryptoModule.decrypt(validPassKeyCopy, ciphertext);

      expect(plaintext).to.equal(validPlaintext);
    });

    it("should decrypt Ciphertext with passphrase and salt", async () => {
      const ciphertext = await CryptoModule.encrypt(validPassphrase, validPlaintext);
      const plaintext = await CryptoModule.decrypt(validPassphrase, ciphertext);

      expect(plaintext).to.equal(validPlaintext);
    });

    it("should throw error if key is passphrase and salt is not provided in ciphertext", async () => {
      const ciphertext = await CryptoModule.encrypt(validKey, validPlaintext);
      expect(ciphertext.salt).to.not.exist;

      try {
        await CryptoModule.decrypt(validPassphrase, ciphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.MISSING_PASSPHRASE_SALT);
      }
    });

    it("should decrypt SharedKey's Ciphertext", async () => {
      const senderPrivateKey = await KeyModule.generatePrivateKey();
      const senderPublicKey = await KeyModule.generatePublicKey({ privateKey: senderPrivateKey });
      const receiverPrivateKey = await KeyModule.generatePrivateKey();
      const receiverPublicKey = await KeyModule.generatePublicKey({ privateKey: receiverPrivateKey });

      const senderSharedKey = await KeyModule.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });
      const senderMessage = "hello world from sender";
      const senderCiphertext = await CryptoModule.encrypt(senderSharedKey, senderMessage);

      const receiverSharedKey = await KeyModule.generateSharedKey({ privateKey: receiverPrivateKey, publicKey: senderPublicKey });
      const receiverMessage = "hello world from receiver";
      const receiverCiphertext = await CryptoModule.encrypt(receiverSharedKey, receiverMessage);

      // reciver should be able to decrypt sender's message
      const decryptedSenderMessage = await CryptoModule.decrypt(receiverSharedKey, senderCiphertext);
      expect(decryptedSenderMessage).to.equal(senderMessage);

      // sender should be able to decrypt receiver's message
      const decryptedReceiverMessage = await CryptoModule.decrypt(senderSharedKey, receiverCiphertext);
      expect(decryptedReceiverMessage).to.equal(receiverMessage);
    });

    it("should throw error if key was not used to encrypt ciphertext", async () => {
      const invalidKey = await KeyModule.generateKey();
      const ciphertext = await CryptoModule.encrypt(validKey, validPlaintext);

      try {
        await CryptoModule.decrypt(invalidKey, ciphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.WRONG_KEY);
      }
    });

    it("should throw an error if key is not a valid passphrase or symmetric key", async () => {
      const invalidKey = await KeyModule.generatePrivateKey() as any;
      const cipherText = await CryptoModule.encrypt(validKey, validPlaintext);

      try {
        await CryptoModule.decrypt(invalidKey, cipherText);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_SYMMETRIC_KEY);
      }
    });

    it("should throw an error if ciphertext is not valid", async () => {
      const cipherText: Ciphertext = "invalid-ciphertext" as any;

      try {
        await CryptoModule.decrypt(validKey, cipherText);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_CIPHERTEXT);
      }
    });
  });

  describe("hash()", () => {
    it("should hash a string", async () => {
      const string = "hello world";
      const hash = await CryptoModule.hash(string);

      expect(hash).to.be.a("string");
    })

    it("should create the same hash for the same string", async () => {
      const string = "hello world";
      const hash1 = await CryptoModule.hash(string);
      const hash2 = await CryptoModule.hash(string);

      expect(hash1).to.equal(hash2);
    })

    it("should create a different hash for a different string", async () => {
      const string1 = "hello world";
      const string2 = "hello world!";
      const hash1 = await CryptoModule.hash(string1);
      const hash2 = await CryptoModule.hash(string2);

      expect(hash1).to.not.equal(hash2);
    })

    it("should throw an error if string is not a string", async () => {
      const string = 123 as any;

      try {
        await CryptoModule.hash(string);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_HASH_STRING);
      }
    })
  })
});