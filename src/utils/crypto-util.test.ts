/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { CRYPTO_ERROR, TEST_ERROR } from "../config/messages";
import { Ciphertext } from "../interfaces/ciphertext-interface";
import { CryptoUtil } from "./crypto-util"
import { WalletUtil } from "./wallet-util";

describe("Crypto Util Test Suite", () => {
  describe("=> Cryptographic Operations", () => {
    describe("encrypt()", () => {
      it("should encrypt a plaintext with a SecretKey and return a Ciphertext", async () => {
        const key = await WalletUtil.generateKey();
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
        const passKey = await WalletUtil.generatePassKey({ passphrase: passphrase });
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
        const senderPrivateKey = await WalletUtil.generatePrivateKey();
        const receiverPrivateKey = await WalletUtil.generatePrivateKey();
        const receiverPublicKey = await WalletUtil.generatePublicKey({ privateKey: receiverPrivateKey });
        
        const sharedKey = await WalletUtil.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });
        
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
        const passKey = await WalletUtil.generatePassKey({ passphrase: passphrase });

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
        const key = await WalletUtil.generateKey();
        const plaintext = "hello world";
        const ciphertext = await CryptoUtil.encrypt(key, plaintext);
        const decryptedPlaintext = await CryptoUtil.decrypt(key, ciphertext);

        expect(decryptedPlaintext).to.equal(plaintext);
      });

      it("should decrypt PassKey's Ciphertext", async () => {
        const passphrase = "password";
        const message = "hello world";

        const encryptPassKey = await WalletUtil.generatePassKey({ passphrase: passphrase });
        const ciphertext = await CryptoUtil.encrypt(encryptPassKey, message);
        const decryptPassKey = await WalletUtil.generatePassKey({ passphrase: passphrase, salt: encryptPassKey.salt });

        const plaintext = await CryptoUtil.decrypt(decryptPassKey, ciphertext);

        expect(message).to.equal(plaintext);
      });

      it("should decrypt SharedKey's Ciphertext", async () => {
        const senderPrivateKey = await WalletUtil.generatePrivateKey();
        const senderPublicKey = await WalletUtil.generatePublicKey({ privateKey: senderPrivateKey });
        const receiverPrivateKey = await WalletUtil.generatePrivateKey();
        const receiverPublicKey = await WalletUtil.generatePublicKey({ privateKey: receiverPrivateKey });

        const senderSharedKey = await WalletUtil.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });
        const senderMessage = "hello world from sender";
        const senderCiphertext = await CryptoUtil.encrypt(senderSharedKey, senderMessage);
        
        const receiverSharedKey = await WalletUtil.generateSharedKey({ privateKey: receiverPrivateKey, publicKey: senderPublicKey });
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
        const key = await WalletUtil.generateKey();
        const invalidKey = await WalletUtil.generateKey();

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
        const key = await WalletUtil.generateKey();
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
});