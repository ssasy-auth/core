/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { TEST_ERROR } from "../config";
import {
  CRYPTO_ERROR_MESSAGE,
  CryptoChecker,
  CryptoModule,
  KeyModule 
} from "../../src/modules";
import type {
  AdvancedCiphertext,
  Ciphertext,
  PassKey,
  PrivateKey,
  SecretKey,
  StandardCiphertext 
} from "../../src/interfaces";
import { BufferUtil } from "../../src/utils";
import { IV_LENGTH, SALT_LENGTH } from "../../src/config";

describe("[CryptoModule Test Suite]", () => {
  let validKey: SecretKey;
  let validPassKey: PassKey;

  const validPassphrase = "password";
  const validPlaintext = "hello world";

  before(async () => {
    validKey = await KeyModule.generateKey();
    validPassKey = await KeyModule.generatePassKey({ passphrase: validPassphrase });
  });
  
  describe("CryptoModule", () => {
  
    describe("encrypt()", () => {
      it("should encrypt a plaintext with a SecretKey and return a Ciphertext", async () => {
        const ciphertext = await CryptoModule.encrypt(validKey, validPlaintext);
  
        // ciphertext should not be the same as plaintext
        expect(ciphertext.data)
          .to.not.equal(validPlaintext)
          .and.to.not.include(validPlaintext);
        // ciphertext should be a base64 string
        expect(BufferUtil.isBase64String(ciphertext.data)).to.be.true;
        // ciphertext should have a iv
        expect(ciphertext.iv).to.exist;
        // iv should be a valid Uint8Array string representation
        const result = BufferUtil.isBufferString(ciphertext.iv);
        expect(result).to.be.true;
      });
  
      it("should encrypt a plaintext with a PassKey and return a Ciphertext", async () => {
        
        const ciphertext = await CryptoModule.encrypt(validPassKey, validPlaintext);
  
        // ciphertext should not be the same as plaintext
        expect(ciphertext.data)
          .to.not.equal(validPlaintext)
          .and.to.not.include(validPlaintext);
        // ciphertext should be a base64 string
        expect(BufferUtil.isBase64String(ciphertext.data)).to.be.true;
        // ciphertext should have a iv
        expect(ciphertext.iv).to.exist;
        // iv should be a valid Uint8Array string representation
        const result = BufferUtil.isBufferString(ciphertext.iv);
        expect(result).to.be.true;
      });
  
      it("should encrypt a plaintext with a passphrase string and return a Ciphertext with passkey salt", async () => {
        const ciphertext = await CryptoModule.encrypt(validPassphrase, validPlaintext);
  
        // ciphertext should not be the same as plaintext
        expect(ciphertext.data)
          .to.not.equal(validPlaintext)
          .and.to.not.include(validPlaintext);
        // ciphertext should be a base64 string
        expect(BufferUtil.isBase64String(ciphertext.data)).to.be.true;
        // ciphertext should have a iv
        expect(ciphertext.iv).to.exist;
        // iv should be a valid Uint8Array string representation
        const ivResult = BufferUtil.isBufferString(ciphertext.iv);
        expect(ivResult).to.be.true;
        // ciphertext should have a salt
        expect(ciphertext.salt).to.exist;
        // salt should be a valid Uint8Array string representation
        const saltResult = BufferUtil.isBufferString(ciphertext.salt as string);
        expect(saltResult).to.be.true;
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
        expect(BufferUtil.isBase64String(ciphertext.data)).to.be.true;
        // ciphertext should have a iv
        expect(ciphertext.iv).to.exist;
        // iv should be a valid Uint8Array string representation
        const result = BufferUtil.isBufferString(ciphertext.iv);
        expect(result).to.be.true;
      });

      it("should attach a valid iv to ciphertext", async () => {
        const ciphertext = await CryptoModule.encrypt(validKey, validPlaintext);
        
        const ivIsBufferString = BufferUtil.isBufferString(ciphertext.iv);
        expect(ivIsBufferString).to.be.true;
        
        const ivBuffer = BufferUtil.StringToBuffer(ciphertext.iv);
        expect(ivBuffer).to.be.instanceOf(Uint8Array);
        expect((ivBuffer as Uint8Array).byteLength).to.equal(IV_LENGTH);
      });

      it("should attach a valid salt to ciphertext if encryption uses passkey", async () => {
        const ciphertext = await CryptoModule.encrypt(validPassKey, validPlaintext);

        expect(ciphertext.salt).to.exist;
        
        const saltIsBufferString = BufferUtil.isBufferString(ciphertext.salt as string);
        expect(saltIsBufferString).to.be.true;

        const saltBuffer = BufferUtil.StringToBuffer(ciphertext.iv);
        expect(saltBuffer).to.be.instanceOf(Uint8Array);
        expect((saltBuffer as Uint8Array).byteLength).to.equal(SALT_LENGTH);
      });
  
      it("should add sender and recipient public keys to ciphertext when provided", async () => {
        const senderPrivateKey = await KeyModule.generatePrivateKey();
        const senderPublicKey = await KeyModule.generatePublicKey({ privateKey: senderPrivateKey });
        const receiverPrivateKey = await KeyModule.generatePrivateKey();
        const receiverPublicKey = await KeyModule.generatePublicKey({ privateKey: receiverPrivateKey });
        const sharedKey = await KeyModule.generateSharedKey({ privateKey: senderPrivateKey, publicKey: receiverPublicKey });
  
        const ciphertext = await CryptoModule.encrypt(sharedKey, validPlaintext, senderPublicKey, receiverPublicKey) as AdvancedCiphertext;
  
        expect(ciphertext.sender).to.deep.equal(senderPublicKey);
        expect(ciphertext.recipient).to.deep.equal(receiverPublicKey);
      });
  
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

    describe("sign()", () => {
      let privateKey: PrivateKey;

      before(async () => {
        privateKey = await KeyModule.generatePrivateKey();
      });

      it("should return a signature object", async () => {
        const signature = await CryptoModule.sign(privateKey, validPlaintext);
        
        expect(signature).to.be.an("object");
      });

      it("should throw an error if key is not a private key", async () => {

        const publicKey = await KeyModule.generatePublicKey({ privateKey });
        
        try {
          await CryptoModule.sign(publicKey as any, validPlaintext);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_SIGNATURE_KEY);
        }

        try {
          await CryptoModule.sign(validKey as any, validPlaintext);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_SIGNATURE_KEY);
        }

        try {
          await CryptoModule.sign(validPassKey as any, validPlaintext);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_SIGNATURE_KEY);
        }
      });
    });

    describe("verify()", () => {
      let privateKey: PrivateKey;
      let ciphertextSignature: AdvancedCiphertext;

      before(async () => {
        privateKey = await KeyModule.generatePrivateKey();

        ciphertextSignature = await CryptoModule.sign(privateKey, validPlaintext);
      });

      it("should return string if signature is valid", async () => {
        const result = await CryptoModule.verify(privateKey, ciphertextSignature);
        expect(result).to.be.a.string;
      });

      it("should return false if private key does not match key that created the signature", async () => {
        const otherPrivateKey = await KeyModule.generatePrivateKey();
        const result = await CryptoModule.verify(otherPrivateKey, ciphertextSignature);

        expect(result).to.be.null;
      });
    });
  
    describe("hash()", () => {
      it("should hash a string", async () => {
        const string = "hello world";
        const hash = await CryptoModule.hash(string);
  
        expect(hash).to.be.a("string");
      });
  
      it("should create the same hash for the same string", async () => {
        const string = "hello world";
        const hash1 = await CryptoModule.hash(string);
        const hash2 = await CryptoModule.hash(string);
  
        expect(hash1).to.equal(hash2);
      });
  
      it("should create a different hash for a different string", async () => {
        const string1 = "hello world";
        const string2 = "hello world!";
        const hash1 = await CryptoModule.hash(string1);
        const hash2 = await CryptoModule.hash(string2);
  
        expect(hash1).to.not.equal(hash2);
      });
  
      it("should throw an error if string is not a string", async () => {
        const string = 123 as any;
  
        try {
          await CryptoModule.hash(string);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(CRYPTO_ERROR_MESSAGE.INVALID_HASH_STRING);
        }
      });
    });

    describe("generateNonce()", () => {
      it("should generate a unique nonce", () => {
        const SAMPLE_SIZE = 100;
        const samples: any[] = [];
        for (let i = 0; i < SAMPLE_SIZE; i++) {
        // create nonce
          const nonce = CryptoModule.generateNonce();
          // check current sample for any identical nonces
          for (let x = 0; x < i; x++) {
            const currNonce = samples[x] as Uint8Array;
            expect(nonce).to.not.deep.equal(currNonce);
          }
          // add nonce to samples
          samples.push(nonce);
        }
      });
    });
  });

  describe("CryptoChecker", () => {
    describe("isCiphertext()", () => {
      let validCiphertext: StandardCiphertext;
      let validPrivateKey: PrivateKey;
      let validSignature: StandardCiphertext;
      let validCiphertextWithSignature: AdvancedCiphertext;

      before(async () => {
        validCiphertext = await CryptoModule.encrypt(validKey, validPlaintext);

        validPrivateKey = await KeyModule.generatePrivateKey();
        validSignature = await CryptoModule.sign(validPrivateKey, validPlaintext);
        
        validCiphertextWithSignature = {
          ...validCiphertext,
          signature: validSignature 
        };
      });
      
      it("should return false if ciphertext does not have valid iv", () => {
        const invalidCiphertext = { ...validCiphertext, iv: BufferUtil.createBuffer(15) };

        // iv must have a length of 16 bytes
        const result = CryptoChecker.isCiphertext(invalidCiphertext);
        expect(result).to.be.false;
      });

      it("should return false if ciphertext does not have valid data", () => {
        const invalidCiphertext = { ...validCiphertext, data: 123 as any };

        // data should be string
        let result = CryptoChecker.isCiphertext(invalidCiphertext);
        expect(result).to.be.false;

        // data should not be empty
        invalidCiphertext.data = "";
        result = CryptoChecker.isCiphertext(invalidCiphertext);
        expect(result).to.be.false;
        
        // data should not be null
        invalidCiphertext.data = null;
        result = CryptoChecker.isCiphertext(invalidCiphertext);
        expect(result).to.be.false;

        // data should not be undefined
        invalidCiphertext.data = undefined;
        result = CryptoChecker.isCiphertext(invalidCiphertext);
        expect(result).to.be.false;
      });

      it("should return false if ciphertext does not have valid salt", () => {
        const invalidCiphertext = { ...validCiphertext, salt: 123 as any };

        // salt should be string
        let result = CryptoChecker.isCiphertext(invalidCiphertext);
        expect(result).to.be.false;

        // salt should not be empty
        invalidCiphertext.salt = "";
        result = CryptoChecker.isCiphertext(invalidCiphertext);
        expect(result).to.be.false;
        
        // salt should not be null
        invalidCiphertext.salt = null;
        result = CryptoChecker.isCiphertext(invalidCiphertext);
        expect(result).to.be.false;

        // salt should not be undefined
        invalidCiphertext.salt = undefined;
        result = CryptoChecker.isCiphertext(invalidCiphertext);
        expect(result).to.be.true;
      });

      it("should return false if the ciphertext has an invalid signature", () => {
        const ciphertextsWithInvalidSignature: Ciphertext[] = [
          { ...validCiphertextWithSignature, signature: "invalid" as any },
          { ...validCiphertextWithSignature, signature: BufferUtil.createBuffer(15) },
          {
            ...validCiphertextWithSignature, 
            signature: { data: "valid string", iv: 123 } // invalid iv
          },
          {
            ...validCiphertextWithSignature, 
            signature: { data: "valid string", iv: BufferUtil.createBuffer(15).toString(), salt: 123 } // invalid salt
          }
        ];

        ciphertextsWithInvalidSignature.forEach((ciphertext) => {
          const result = CryptoChecker.isCiphertext(ciphertext);
          expect(result).to.be.false;
        });
      });
      
      it("should return true if ciphertext is valid", () => {
        const ciphertextWithoutSalt = { ...validCiphertext, salt: undefined };

        // should return true if salt is undefined
        let result = CryptoChecker.isCiphertext(ciphertextWithoutSalt);
        expect(result).to.be.true;

        result = CryptoChecker.isCiphertext(validCiphertext);
        expect(result).to.be.true;
      });

      it("should return true if the ciphertext has a valid signature", () => {
        const result = CryptoChecker.isCiphertext(validCiphertextWithSignature);
        expect(result).to.be.true;
      });

      it("should return true if valid signature is passed instead of ciphertext", () => {
        const signature = validCiphertextWithSignature.signature as any;
        const result = CryptoChecker.isCiphertext(signature);
        expect(result).to.be.true;
      });
    });
  });
});