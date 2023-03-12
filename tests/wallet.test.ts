/* eslint-disable @typescript-eslint/no-explicit-any */
import { expect } from "chai";
import { TEST_ERROR } from "./config";
import { BufferUtil } from "../src/utils";
import {
  KeyModule, CryptoModule, EncoderModule 
} from "../src/modules";
import { Wallet, WALLET_ERROR_MESSAGE } from "../src/wallet";
import type { Ciphertext } from "../src/interfaces/ciphertext-interface";
import type { KeyPair, PrivateKey } from "../src/interfaces/key-interface";

describe("[Wallet Class Test Suite]", () => {
  const validPassphrase = "passphrase";
  const validKeyPair: KeyPair = {
 
  } as KeyPair;
  const validFriendKeyPair: KeyPair = {
 
  } as KeyPair;
  const validThirdPartyKeyPair: KeyPair = {
 
  } as KeyPair;

  before(async () => {
    // Generate a keypair
    validKeyPair.private = await KeyModule.generatePrivateKey();
    validKeyPair.public = await KeyModule.generatePublicKey({
      privateKey: validKeyPair.private 
    });

    // Generate a friend keypair
    validFriendKeyPair.private = await KeyModule.generatePrivateKey();
    validFriendKeyPair.public = await KeyModule.generatePublicKey({
      privateKey: validFriendKeyPair.private 
    });

    // Generate a third party keypair
    validThirdPartyKeyPair.private = await KeyModule.generatePrivateKey();
    validThirdPartyKeyPair.public = await KeyModule.generatePublicKey({
      privateKey: validThirdPartyKeyPair.private 
    });
  })

  describe("constructor()", () => {
    it("should throw an error if invalid private key is provided", async () => {
      try {
        new Wallet("invalid" as unknown as PrivateKey);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_KEY);
      }

      try {
        new Wallet(validKeyPair.public as unknown as PrivateKey);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_KEY);
      }
    })
    
    it("should throw an error if key is not provided", async () => {
      try {
        new Wallet(undefined as unknown as PrivateKey);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CONSTRUCTOR_PARAMS);
      }
    })

    it("should return a wallet instance if valid private key is provided", async () => {
      const wallet = new Wallet(validKeyPair.private);
      expect(wallet).to.be.instanceOf(Wallet);
    })

    // Don't know how to test this
    it("should not expose private key")
  })

  describe("encrypt()", () => {
    let wallet: Wallet;

    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);
    })

    it("should throw an error if key is not supported", async () => {
      try {
        await wallet.encrypt(validKeyPair.private as any, "data");
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_KEY);
      }

      try {
        const invalidKey = await KeyModule.generateKey() as any;
        await wallet.encrypt(invalidKey, "data");
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_KEY);
      }
    })

    it("should throw an error if data is not provided", async () => {
      try {
        await wallet.encrypt(validFriendKeyPair.public, undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_PAYLOAD);
      }
    })

    it("should return an encrypted ciphertext", async () => {
      const payload = "data";
      const ciphertext = await wallet.encrypt(validFriendKeyPair.public, payload);
      expect(ciphertext.data).to.not.equal(payload);
      expect(ciphertext.data).to.not.include(payload);
      // iv should be a valid Uint8Array string representation
      const result = BufferUtil.isBufferString(ciphertext.iv);
      expect(result).to.be.true;
    })

    it("should return an encrypted ciphertext with sender as wallet public key and recipient as provided public key", async () => {
      const payload = "data";
      const ciphertext = await wallet.encrypt(validFriendKeyPair.public, payload);
      
      expect(ciphertext.sender).to.deep.equal(validKeyPair.public); // wallet public key
      expect(ciphertext.recipient).to.deep.equal(validFriendKeyPair.public);
    })

    it("should return an encrypted ciphertext with salt if key is a string", async () => {
      const payload = "data";
      const ciphertext = await wallet.encrypt(validPassphrase, payload);
      expect(ciphertext.salt).to.exist;
    })
  })

  describe("decrypt()", () => {
    let wallet: Wallet;

    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);
    })

    it("should throw an error if key is not supported", async () => {
      const ciphertext = await wallet.encrypt(validFriendKeyPair.public, "data");
      try {
        await wallet.decrypt(validKeyPair.private as any, ciphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_KEY);
      }

      try {
        const invalidKey = await KeyModule.generateKey() as any;
        await wallet.decrypt(invalidKey, ciphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_KEY);
      }
    })
    
    it("should throw an error if ciphertext is not provided", async () => {
      try {
        await wallet.decrypt(validPassphrase, undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
      }
    })

    it("should return decrypted data", async () => {
      const payload = "data";
      const ciphertext = await wallet.encrypt(validKeyPair.public, payload);
      const decrypted = await wallet.decrypt(validKeyPair.public, ciphertext);
      expect(decrypted).to.equal(payload);
    })
  })

  describe("generateChallenge()", () => {
    let wallet: Wallet;

    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);
    })

    it("should return a challenge as a ciphertext", async () => {
      const ciphertext = await wallet.generateChallenge(validFriendKeyPair.public);
      expect(ciphertext.data).to.exist;
      expect(ciphertext.iv).to.exist;
    });

    it("should set ciphertext sender to the wallet public key and recipient to the provided public key", async () => {
      const ciphertext = await wallet.generateChallenge(validFriendKeyPair.public);
      expect(ciphertext.sender).to.deep.equal(validKeyPair.public); // wallet public key
      expect(ciphertext.recipient).to.deep.equal(validFriendKeyPair.public);
    });
  })

  describe("solveChallenge()", () => {
    let wallet: Wallet;
    let friendWallet: Wallet;
    let ciphertext: Ciphertext; // generated by friend wallet

    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);
      friendWallet = new Wallet(validFriendKeyPair.private);
      ciphertext = await friendWallet.generateChallenge(validKeyPair.public);
    })

    it("should throw an error if the ciphertext is not provided", async () => {
      try {
        await wallet.solveChallenge(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
      }
    })

    it("should throw an error if the sender or recipient is not provided in ciphertext", async () => {
      delete ciphertext.sender;
      delete ciphertext.recipient;
      
      try {
        await wallet.solveChallenge(ciphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_PARTIES);
      }
    })

    it("should throw an error if the ciphertext recipient does not match the wallet public key", async () => {
      ciphertext.recipient = validFriendKeyPair.public;
      
      try {
        await wallet.solveChallenge(ciphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
      }
    })
    
    it("should throw an error if the challenge is not provided", async () => {
      ciphertext.data = undefined as any;
      
      try {
        await wallet.solveChallenge(ciphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
      }
    })
    
    it("should return a solved challenge as a ciphertext", async () => {
      const solvedCiphertext = await wallet.solveChallenge(ciphertext);
      expect(solvedCiphertext.data).to.exist;
      expect(solvedCiphertext.iv).to.exist;
    })

    it("should set ciphertext sender to the claimant's public key and recipient to the verifier's public key", async () => {
      const sharedKey = await KeyModule.generateSharedKey({
        privateKey: validKeyPair.private, publicKey: validFriendKeyPair.public 
      });
      
      const decryptedChallenge = await CryptoModule.decrypt(sharedKey, ciphertext);
      const challenge = await EncoderModule.decodeChallenge(decryptedChallenge);

      const solvedCiphertext = await wallet.solveChallenge(ciphertext);
      expect(solvedCiphertext.sender).to.deep.equal(challenge.claimant);
      expect(solvedCiphertext.recipient).to.deep.equal(challenge.verifier);
    })
  })

  describe("verifyChallenge()", () => {
    let wallet: Wallet;
    let friendWallet: Wallet;
    let ciphertext: Ciphertext;
    let solvedCiphertext: Ciphertext;
    
    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);
      friendWallet = new Wallet(validFriendKeyPair.private);
      
      ciphertext = await wallet.generateChallenge(validFriendKeyPair.public); // generate challenge for friend
      solvedCiphertext = await friendWallet.solveChallenge(ciphertext); // friend solves challenge
    })

    it("should throw an error if the ciphertext is not provided", async () => {
      try {
        await wallet.verifyChallenge(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
      }
    })

    it("should throw an error if the sender or recipient is not provided in ciphertext", async () => {
      delete solvedCiphertext.sender;
      delete solvedCiphertext.recipient;

      try {
        await wallet.verifyChallenge(solvedCiphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_PARTIES);
      }
    })

    it("should throw an error if the ciphertext recipient does not match the wallet public key", async () => {
      const thirdPartyWallet = new Wallet(validThirdPartyKeyPair.private);
      const notYourChallenge = await friendWallet.generateChallenge(validThirdPartyKeyPair.public); // friend generates challenge for third party
      const notYourSolvedCiphertext = await thirdPartyWallet.solveChallenge(notYourChallenge); // third party solves challenge

      try {
        await wallet.verifyChallenge(notYourSolvedCiphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
      }
    })

    it("should throw an error if the challenge is not provided", async () => {
      try {
        await wallet.verifyChallenge(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
      }
    })

    it("should return claimant's public key if the challenge has been solved", async () => {
      const claimantPublicKey = await wallet.verifyChallenge(solvedCiphertext);
      expect(claimantPublicKey).to.deep.equal(validFriendKeyPair.public);
    })

    it("should return null if the challenge has not been solved", async () => {
      const ciphertext = await wallet.generateChallenge(validFriendKeyPair.public);
      ciphertext.sender = validFriendKeyPair.public;
      ciphertext.recipient = validKeyPair.public;
      
      const claimantPublicKey = await wallet.verifyChallenge(ciphertext);
      expect(claimantPublicKey).to.be.null;
    })
  })
})