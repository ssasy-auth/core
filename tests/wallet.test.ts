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
  AdvancedCiphertext,
  Challenge,
  KeyPair,
  PrivateKey,
  PublicKey,
  StandardCiphertext
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
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
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
      expect(isValid).to.not.be.null;
    });
  });

  describe("verify()", () => {
    it("should return encoded challenge if signature is valid", async () => {
      const wallet = new Wallet(validKeyPair.private);
      const payload = "data";
      const ciphertext: StandardCiphertext = await wallet.sign(payload);
      const result: string | null = await wallet.verify(ciphertext);
      expect(result).to.be.a.string;
    });

    it("should return null if signature is invalid", async () => {
      const friendWallet = new Wallet(validFriendKeyPair.private);
      const payload = "data";
      const ciphertext = await friendWallet.sign(payload);
      
      const wallet = new Wallet(validKeyPair.private);
      const isValid = await wallet.verify(ciphertext);
      expect(isValid).to.be.null;
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

    it("should return ciphertext with signature if signature is provided", async () => {
      // create a challenge so that friend can solve it
      const encryptedChallenge: AdvancedCiphertext = await wallet.generateChallenge(validFriendKeyPair.public);

      // friend solves the challenge and adds their signature
      const friendWallet: Wallet = new Wallet(validFriendKeyPair.private);
      const solutionWithSignature: AdvancedCiphertext = await friendWallet.solveChallenge(encryptedChallenge);

      // function under test
      const newEncryptedChallenge: AdvancedCiphertext = await wallet.generateChallenge(validFriendKeyPair.public, solutionWithSignature.signature);

      expect(newEncryptedChallenge.signature).to.deep.equal(solutionWithSignature.signature);
    })

    it("should set ciphertext sender to the wallet public key and recipient to the provided public key", async () => {
      const ciphertext = await wallet.generateChallenge(validFriendKeyPair.public);
      
      expect(ciphertext.sender).to.deep.equal(validKeyPair.public); // wallet public key
      expect(ciphertext.recipient).to.deep.equal(validFriendKeyPair.public);
    });
  })

  describe("solveChallenge()", () => {
    let wallet: Wallet;
    let challenge: Challenge; // generated by friend wallet
    let challengeCiphertext: AdvancedCiphertext; // generated by friend wallet

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
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
      }
    })

    it("should throw an error if the sender or recipient is not provided in ciphertext", async () => {
      const mockCiphertext: AdvancedCiphertext = {
        ...challengeCiphertext,
        sender: undefined as any, // <-- should be friend public key
        recipient: undefined as any // <-- should be wallet public key
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
      const mockCiphertext: AdvancedCiphertext = {
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
      const mockCiphertext: AdvancedCiphertext = {
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

    it("should return a ciphertext challenge with solution", async () => {
      const solutionCiphertext = await wallet.solveChallenge(challengeCiphertext);

      expect(solutionCiphertext.data).to.exist;
      expect(solutionCiphertext.iv).to.exist;
    })

    it("should return a ciphertext with a signature", async () => {
      const solutionCiphertext = await wallet.solveChallenge(challengeCiphertext);

      expect(solutionCiphertext.signature).to.exist;
      const isValidCiphertext = CryptoChecker.isCiphertext(solutionCiphertext);
      expect(isValidCiphertext).to.be.true;
    });

    it("should return a signature that matches the solved challenger", async () => {
      const solutionCiphertext = await wallet.solveChallenge(challengeCiphertext);
      
      // extract solution from ciphertext
      const sharedKey = await KeyModule.generateSharedKey({
        privateKey: validKeyPair.private, publicKey: challengeCiphertext.sender as PublicKey 
      });
      const decryptedSolution = await CryptoModule.decrypt(sharedKey, solutionCiphertext)
      const solution = await EncoderModule.decodeChallenge(decryptedSolution);
      
      const signature = solutionCiphertext.signature as StandardCiphertext;
      const encodedChallengeSolution: string = await wallet.verify(signature) as string;
      const challengeSolution: Challenge = await EncoderModule.decodeChallenge(encodedChallengeSolution);
      
      expect(challengeSolution).to.deep.equal(solution);
    });

    it("should return a signature that is verifiable by the wallet", async () => {
      const solutionCiphertext = await wallet.solveChallenge(challengeCiphertext);
      const signature = solutionCiphertext.signature as StandardCiphertext;

      const isValidSignature = await wallet.verify(signature)
      expect(isValidSignature).to.not.be.null;
    });

    it("should set ciphertext sender to the claimant's public key and recipient to the verifier's public key", async () => {
      // solve challenge
      const solutionCiphertext = await wallet.solveChallenge(challengeCiphertext);

      expect(solutionCiphertext.sender).to.deep.equal(challenge.claimant);
      expect(solutionCiphertext.recipient).to.deep.equal(challenge.verifier);
    })
  })

  describe("solveChallenge() with required signature", () => {
    let wallet: Wallet;
    let challenge: Challenge; // generated by friend wallet
    let challengeCiphertext: AdvancedCiphertext; // generated by friend wallet

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

    it("should throw an error if ciphertext does not contain a signature", async () => {
      try {
        await wallet.solveChallenge(challengeCiphertext, {
          requireSignature: true
        });
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (err) {
        const error = err as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE);
      }
    })
    
    it("should throw an error if challenge signature is invalid", async () => {
      const ciphertextsWithInvalidSignature = [
        {
          ...challengeCiphertext, signature: "invalid"
        },
        {
          ...challengeCiphertext, signature: undefined as any
        },
        {
          ...challengeCiphertext, signature: null as any
        }
      ];

      for (const ciphertext of ciphertextsWithInvalidSignature) {
        try {
          await wallet.solveChallenge(ciphertext, {
            requireSignature: true
          });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (err) {
          const error = err as Error;
          const isExpectedMessage = error.message === WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE || error.message === WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT;
          expect(isExpectedMessage).to.be.true;
        }
      }
    })

    it("should throw an error if challenge signature does not match parties", async () => {
      /**
       * scenario:
       * 
       * 1. friend wallet generates challenge
       * 2. you solve the challenge and attach your signature
       * 3. third-party wallet
       *    - captures the signature
       *    - tries to replay it with a different public key (not the friend's)
       */

      // step 1. friend wallet generates challenge
      const friendWallet: Wallet = new Wallet(validFriendKeyPair.private);
      const walletChallengeCiphertext: AdvancedCiphertext = await friendWallet.generateChallenge(validKeyPair.public);

      // step 2. you solve the challenge and attach your signature
      const walletSolutionCiphertext: AdvancedCiphertext = await wallet.solveChallenge(walletChallengeCiphertext);

      // step 3. third-party wallet captures the signature and tries to replay it with a different public key (not the friend's)
      const thirdPartyWallet: Wallet = new Wallet(validThirdPartyKeyPair.private);
      const thirdPartyChallengeCiphertext: AdvancedCiphertext = {
        ...await thirdPartyWallet.generateChallenge(validKeyPair.public), 
        signature: walletSolutionCiphertext.signature
      }

      try {
        await wallet.solveChallenge(thirdPartyChallengeCiphertext, {
          requireSignature: true 
        });
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (err) {
        const error = err as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_SIGNATURE_ORIGIN);
      }

    });

    it("should return solution if valid signature is provided", async () => {
      const friendWallet: Wallet = new Wallet(validFriendKeyPair.private);
      const encryptedFriendChallenge = await friendWallet.generateChallenge(validKeyPair.public);

      // produce solution with signature
      const encryptedSolutionWithSignature = await wallet.solveChallenge(encryptedFriendChallenge);

      // ... friend saves signature

      // friend generates a new challenge with signature
      const newEncryptedFriendChallenge = await friendWallet.generateChallenge(validKeyPair.public, encryptedSolutionWithSignature.signature);

      // ... friend sends challenge to wallet

      // wallet solves challenge with signature
      const walletSolutionWithSignature = await wallet.solveChallenge(newEncryptedFriendChallenge, { requireSignature: true });

      expect(walletSolutionWithSignature).to.not.be.null;
    });
  })

  describe("verifyChallenge()", () => {
    let wallet: Wallet; // <- verifier
    let friendWallet: Wallet; // <- claimant
    
    let challengeCiphertext: AdvancedCiphertext; // generated by verifier
    let solutionCiphertext: AdvancedCiphertext; // generated by claimant

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
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
      }
    })

    it("should throw an error if the sender or recipient is not provided in ciphertext", async () => {
      const mockSolutionCiphertext: AdvancedCiphertext = {
        ...solutionCiphertext,
        sender: undefined as any, // <-- should be wallet public key
        recipient: undefined as any // <-- should be friend public key
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
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
      }
    })

    it("should return object with claimant's public key if the challenge has been solved", async () => {
      const result = await wallet.verifyChallenge(solutionCiphertext);
      expect(result).to.be.an("object");
      expect(result).to.have.property("publicKey");
      expect(result?.publicKey).to.deep.equal(validFriendKeyPair.public);
    })

    it("should return object with signature if ciphertext had a signature and the challenge has been solved", async () => {
      expect(solutionCiphertext.signature).to.exist;
      
      const result = await wallet.verifyChallenge(solutionCiphertext);
      expect(result).to.be.an("object");
      expect(result).to.have.property("signature");

      const isCiphertext = CryptoChecker.isCiphertext(result?.signature as StandardCiphertext);
      expect(isCiphertext).to.be.true;
    })

    it("should return object with signature that is verifiable by claimant if ciphertext had a signature and the challenge has been solved", async () => {
      expect(solutionCiphertext.signature).to.exist;
      
      const result = await wallet.verifyChallenge(solutionCiphertext);
      const isValidSignature = await friendWallet.verify(result?.signature as StandardCiphertext);
      expect(isValidSignature).to.not.be.null;
    })

    it("should return null if the challenge has not been solved", async () => {
      const mockSolutionCiphertext: AdvancedCiphertext = {
        ...solutionCiphertext,
        data: challengeCiphertext.data // <-- should be solution
      }

      const claimantPublicKey = await wallet.verifyChallenge(mockSolutionCiphertext);
      expect(claimantPublicKey).to.be.null;
    })
  })
});