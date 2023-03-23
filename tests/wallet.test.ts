/* eslint-disable @typescript-eslint/no-explicit-any */
import { expect } from "chai";
import { TEST_ERROR } from "./config";
import { BufferUtil } from "../src/utils";
import {
  KeyModule,
  CryptoModule,
  EncoderModule, 
  ChallengeModule,
  CryptoChecker
} from "../src/modules";
import { Wallet, WALLET_ERROR_MESSAGE } from "../src/wallet";
import type {
  Ciphertext,
  Challenge,
  KeyPair,
  PrivateKey
} from "../src/interfaces";

describe("[Wallet Class Test Suite]", () => {
  const validPassphrase = "passphrase";
  const validKeyPair = {
 
  } as KeyPair;
  const validFriendKeyPair = {
 
  } as KeyPair;
  const validThirdPartyKeyPair = {
 
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

  describe("sign()", () => {
    let wallet: Wallet;

    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);
    })

    it("should return a ciphertext", async () => {
      const payload = "data";
      const ciphertext = await wallet.sign(payload);
      
      expect(ciphertext).to.be.an("object");

      const isCiphertext = CryptoChecker.isCiphertext(ciphertext);
      expect(isCiphertext).to.be.true;
    });

    it("should create signature based on wallet private key", async () => {
      const payload = "data";
      const ciphertext = await wallet.sign(payload);
      const isValid = await CryptoModule.verify(validKeyPair.private, ciphertext);
      expect(isValid).to.be.true;
    });
  });

  describe("verify()", () => {
    it("should return true if signature is valid", async () => {
      const wallet = new Wallet(validKeyPair.private);
      const payload = "data";
      const ciphertext = await wallet.sign(payload);
      const isValid = await wallet.verify(ciphertext);
      expect(isValid).to.be.true;
    });

    it("should return false if signature is invalid", async () => {
      const friendWallet = new Wallet(validFriendKeyPair.private);
      const payload = "data";
      const ciphertext = await friendWallet.sign(payload);
      
      const wallet = new Wallet(validKeyPair.private);
      const isValid = await wallet.verify(ciphertext);
      expect(isValid).to.be.false;
    });
  });

  describe("generateChallenge()", () => {
    let wallet: Wallet;

    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);
    })

    it("should return an object", async () => {
      const result = await wallet.generateChallenge(validFriendKeyPair.public);
      expect(result).to.be.an("object");
    });

    it("should return an encoded ciphertext of the challenge", async () => {
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
    let challenge: Challenge; // generated by friend wallet
    let challengeCiphertext: Ciphertext; // generated by friend wallet

    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);
      

      // set challenge
      challenge = await ChallengeModule.generateChallenge(validFriendKeyPair.private, validKeyPair.public);

      // encode challenge
      const encodedChallenge = await EncoderModule.encodeChallenge(challenge);

      // encrypt challenge
      const sharedKey = await KeyModule.generateSharedKey({
        privateKey: validFriendKeyPair.private, publicKey: validKeyPair.public
      });

      challengeCiphertext = await CryptoModule.encrypt(sharedKey, encodedChallenge, validFriendKeyPair.public, validKeyPair.public);
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
      const mockCiphertext: Ciphertext = {
        ...challengeCiphertext,
        sender: undefined, // <-- should be friend public key
        recipient: undefined // <-- should be wallet public key
      }
      
      try {
        await wallet.solveChallenge(mockCiphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_PARTIES);
      }
    })

    it("should throw an error if the ciphertext recipient does not match the wallet public key", async () => {
      const mockCiphertext: Ciphertext = {
        ...challengeCiphertext,
        recipient: validFriendKeyPair.public // <-- should be wallet public key
      }
      
      try {
        await wallet.solveChallenge(mockCiphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
      }
    })
    
    it("should throw an error if invalid challenge is provided", async () => {
      const mockCiphertext: Ciphertext = {
        ...challengeCiphertext,
        data: "invalid" // <-- should be challenge
      }

      try {
        await wallet.solveChallenge(mockCiphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
      }
    })
    
    it("should return a solved challenge as a ciphertext", async () => {
      const solutionCiphertext = await wallet.solveChallenge(challengeCiphertext);

      expect(solutionCiphertext.data).to.exist;
      expect(solutionCiphertext.iv).to.exist;
    })

    it("should set ciphertext sender to the claimant's public key and recipient to the verifier's public key", async () => {
      // solve challenge
      const solutionCiphertext = await wallet.solveChallenge(challengeCiphertext);

      expect(solutionCiphertext.sender).to.deep.equal(challenge.claimant);
      expect(solutionCiphertext.recipient).to.deep.equal(challenge.verifier);
    })
  })

  describe("verifyChallenge()", () => {
    let wallet: Wallet; // <- verifier
    let friendWallet: Wallet; // <- claimant
    
    let challengeCiphertext: Ciphertext; // generated by verifier
    let solutionCiphertext: Ciphertext; // generated by claimant

    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);
      friendWallet = new Wallet(validFriendKeyPair.private);
      
      challengeCiphertext = await wallet.generateChallenge(validFriendKeyPair.public)
      solutionCiphertext = await friendWallet.solveChallenge(challengeCiphertext)
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
      const mockSolutionCiphertext: Ciphertext = {
        ...solutionCiphertext,
        sender: undefined, // <-- should be wallet public key
        recipient: undefined // <-- should be friend public key
      }

      try {
        await wallet.verifyChallenge(mockSolutionCiphertext);
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
      const claimantPublicKey = await wallet.verifyChallenge(solutionCiphertext);
      expect(claimantPublicKey).to.deep.equal(validFriendKeyPair.public);
    })

    it("should return null if the challenge has not been solved", async () => {
      const mockSolutionCiphertext: Ciphertext = {
        ...solutionCiphertext,
        data: challengeCiphertext.data // <-- should be solution
      }

      const claimantPublicKey = await wallet.verifyChallenge(mockSolutionCiphertext);
      expect(claimantPublicKey).to.be.null;
    })
  })
});