/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { TEST_ERROR } from "../config";
import { Ciphertext } from "../../src/interfaces/ciphertext-interface";
import { KeyModule } from "../../src/modules/key-mod";
import { CryptoModule, CRYPTO_ERROR_MESSAGE } from "../../src/modules/crypto-mod";

describe("CryptoModule Test Suite", () => {
  describe("encrypt()", () => {
    it("should encrypt a plaintext with a SecretKey and return a Ciphertext", async () => {
      const key = await KeyModule.generateKey();
      const plaintext = "hello world";
      const ciphertext = await CryptoModule.encrypt(key, plaintext);

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
      const passKey = await KeyModule.generatePassKey({ passphrase: passphrase });
      const plaintext = "hello world";

      const ciphertext = await CryptoModule.encrypt(passKey, plaintext);

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
      const senderPrivateKey = await KeyModule.generatePrivateKey();
      const receiverPrivateKey = await KeyModule.generatePrivateKey();
      const receiverPublicKey = await KeyModule.generatePublicKey({ privateKey: receiverPrivateKey });

      const sharedKey = await KeyModule.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });

      const plaintext = "hello world";
      const ciphertext = await CryptoModule.encrypt(sharedKey, plaintext);

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
        await CryptoModule.encrypt(key, plaintext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_SYMMETRIC_KEY);
      }
    });

    it("should throw an error if plaintext is not a string", async () => {
      const passphrase = "password";
      const passKey = await KeyModule.generatePassKey({ passphrase: passphrase });

      const plaintext = 123 as any;

      try {
        await CryptoModule.encrypt(passKey, plaintext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_PLAINTEXT);
      }
    });
  });

  describe("decrypt()", () => {
    it("should decrypt SecretKey's Ciphertext", async () => {
      const key = await KeyModule.generateKey();
      const plaintext = "hello world";
      const ciphertext = await CryptoModule.encrypt(key, plaintext);
      const decryptedPlaintext = await CryptoModule.decrypt(key, ciphertext);

      expect(decryptedPlaintext).to.equal(plaintext);
    });

    it("should decrypt PassKey's Ciphertext", async () => {
      const passphrase = "password";
      const message = "hello world";

      const encryptPassKey = await KeyModule.generatePassKey({ passphrase: passphrase });
      const ciphertext = await CryptoModule.encrypt(encryptPassKey, message);
      const decryptPassKey = await KeyModule.generatePassKey({ passphrase: passphrase, salt: encryptPassKey.salt });

      const plaintext = await CryptoModule.decrypt(decryptPassKey, ciphertext);

      expect(message).to.equal(plaintext);
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
      const key = await KeyModule.generateKey();
      const invalidKey = await KeyModule.generateKey();

      const plaintext = "hello world";
      const ciphertext = await CryptoModule.encrypt(key, plaintext);


      try {
        await CryptoModule.decrypt(invalidKey, ciphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.WRONG_KEY);
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
        await CryptoModule.decrypt(key, cipherText);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error: Error = e as Error;
        expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_SYMMETRIC_KEY);
      }
    });

    it("should throw an error if ciphertext is not valid", async () => {
      const key = await KeyModule.generateKey();
      const cipherText: Ciphertext = "invalid-ciphertext" as any;

      try {
        await CryptoModule.decrypt(key, cipherText);
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