/* eslint-disable @typescript-eslint/no-explicit-any */
import { expect } from "chai";
import { TEST_ERROR } from "./config";
import { BufferUtil } from "../src/utils";
import {
  KeyModule,
  CryptoModule,
  EncoderModule, 
  ChallengeModule,
  KeyChecker
} from "../src/modules";
import { Wallet, WALLET_ERROR_MESSAGE } from "../src/wallet";
import type {
  Ciphertext,
  Challenge,
  KeyPair,
  PrivateKey,
  PublicKey
} from "../src/interfaces";


/**
 * [START] ========================= HaCkeY Mocks of some wallet functions =========================
 * 
 * Before I begin, I would like to apologize for the following test suite. I am not proud of it.
 * 
 * Below is a hackey way to mimick the `wallet.generateChallenge()` method so that the 
 * ciphertext can manipulate for the purpose of testing the `wallet.solveChallenge()` 
 * and `wallet.verifyChallenge()` methods.
 * 
 * TODO: Need to find a better way to test this
 */

interface TestChallenge {
  challenge: Challenge;
  encodedChallenge: string;
  challengeCiphertext: Ciphertext;
  encodedChallengeCiphertext: string;
}
async function mockWalletGenerateChallenge(
  verifierPrivateKey: PrivateKey, 
  verifierPublicKey: PublicKey, 
  claimantPublicKey: PublicKey
): Promise<TestChallenge> {
  // generate a challenge
  const challenge = await ChallengeModule.generateChallenge(verifierPrivateKey, claimantPublicKey);
  // encode the challenge
  const encodedChallenge = await EncoderModule.encodeChallenge(challenge);
  // get the wallet's public key
  const publicKey = verifierPublicKey;
  // generate a shared key
  const sharedKey = await KeyModule.generateSharedKey({
    privateKey: verifierPrivateKey, publicKey: claimantPublicKey
  });
    
  // encrypt the challenge with the shared key and return it
  const challengeCiphertext = await CryptoModule.encrypt(sharedKey, encodedChallenge, publicKey, claimantPublicKey);

  const encodedChallengeCiphertext = await EncoderModule.encodeCiphertext(challengeCiphertext);

  return {
    challenge,
    encodedChallenge,
    challengeCiphertext,
    encodedChallengeCiphertext
  }
}

interface TestSolution {
  solution: Challenge;
  encodedSolution: string;
  solutionCiphertext: Ciphertext;
  encodedSolutionCiphertext: string;
}
async function mockWalletSolveSolution(
  claimantPrivateKey: PrivateKey,
  claimantPublicKey: PublicKey,
  encodedCiphertextForChallenge: string
): Promise<TestSolution>{
  if (!encodedCiphertextForChallenge) {
    throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
  }

  // decode the ciphertext
  const ciphertext = await EncoderModule.decodeCiphertext(encodedCiphertextForChallenge);

  if (!ciphertext.data) {
    throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
  }

  if(!ciphertext.sender || !ciphertext.recipient) {
    throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_PARTIES);
  }
    
  const publicKey = claimantPublicKey;

  // throw error if the ciphertext is not meant for claimant
  const recipientMatchesWallet = await KeyChecker.isSameKey(ciphertext.recipient, publicKey);
  if (!recipientMatchesWallet) {
    throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
  }
    
  // generate a shared key
  const sharedKey = await KeyModule.generateSharedKey({
    privateKey: claimantPrivateKey, publicKey: ciphertext.sender 
  });
    // decrypt the challenge
  const encodedChallenge = await CryptoModule.decrypt(sharedKey, ciphertext);
  const challenge = await EncoderModule.decodeChallenge(encodedChallenge);

  // throw error if the challenge is not meant for claimant
  if(!await KeyChecker.isSameKey(challenge.claimant, publicKey)) {
    throw new Error(WALLET_ERROR_MESSAGE.INVALID_CHALLENGE_ORIGIN);
  }

  // solve the challenge
  const solution = await ChallengeModule.solveChallenge(claimantPrivateKey, challenge);
  // encode the solved challenge
  const encodedSolution = await EncoderModule.encodeChallenge(solution);
  // encrypt the solved challenge with the shared key and return it
  const solutionCiphertext = await CryptoModule.encrypt(sharedKey, encodedSolution, publicKey, ciphertext.sender);

  const encodedSolutionCiphertext = await EncoderModule.encodeCiphertext(solutionCiphertext);

  return {
    solution,
    encodedSolution,
    solutionCiphertext,
    encodedSolutionCiphertext
  }
}

/** [END] ========================= HaCkeY Mocks of some wallet functions ========================= */

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

    it("should return a string", async () => {
      const result = await wallet.generateChallenge(validFriendKeyPair.public);
      expect(result).to.be.a("string");
    });

    it("should return an encoded ciphertext of the challenge", async () => {
      const ciphertext = await wallet.generateChallenge(validFriendKeyPair.public);
      
      const decodedCiphertext = await EncoderModule.decodeCiphertext(ciphertext);
      expect(decodedCiphertext.data).to.exist;
      expect(decodedCiphertext.iv).to.exist;
    });

    it("should set ciphertext sender to the wallet public key and recipient to the provided public key", async () => {
      const ciphertext = await wallet.generateChallenge(validFriendKeyPair.public);
      
      const decodedCiphertext = await EncoderModule.decodeCiphertext(ciphertext);
      expect(decodedCiphertext.sender).to.deep.equal(validKeyPair.public); // wallet public key
      expect(decodedCiphertext.recipient).to.deep.equal(validFriendKeyPair.public);
    });
  })

  describe("solveChallenge()", () => {
    let wallet: Wallet;
    let challenge: Challenge; // generated by friend wallet
    let challengeCiphertext: Ciphertext; // generated by friend wallet
    let encodedChallengeCiphertext: string; // generated by friend wallet

    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);

      const mockChallenge = await mockWalletGenerateChallenge(
        validFriendKeyPair.private,
        validFriendKeyPair.public,
        validKeyPair.public
      )

      challenge = mockChallenge.challenge;
      challengeCiphertext = mockChallenge.challengeCiphertext;
      encodedChallengeCiphertext = mockChallenge.encodedChallengeCiphertext;
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

      const invalidEncodedCiphertext = await EncoderModule.encodeCiphertext(mockCiphertext);
      
      try {
        await wallet.solveChallenge(invalidEncodedCiphertext);
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
      
      const invalidEncodedCiphertext = await EncoderModule.encodeCiphertext(mockCiphertext);
      
      try {
        await wallet.solveChallenge(invalidEncodedCiphertext);
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
        const invalidEncodedCiphertext = await EncoderModule.encodeCiphertext(mockCiphertext);
        await wallet.solveChallenge(invalidEncodedCiphertext);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
      }
    })
    
    it("should return a solved challenge as a ciphertext", async () => {
      const solvedCiphertext = await wallet.solveChallenge(encodedChallengeCiphertext);
      const decodedCiphertext = await EncoderModule.decodeCiphertext(solvedCiphertext);

      expect(decodedCiphertext.data).to.exist;
      expect(decodedCiphertext.iv).to.exist;
    })

    it("should set ciphertext sender to the claimant's public key and recipient to the verifier's public key", async () => {
      // solve challenge
      const encodedCiphertext = await wallet.solveChallenge(encodedChallengeCiphertext);
      
      // decode ciphertext
      const decodedCiphertext = await EncoderModule.decodeCiphertext(encodedCiphertext);
      expect(decodedCiphertext.sender).to.deep.equal(challenge.claimant);
      expect(decodedCiphertext.recipient).to.deep.equal(challenge.verifier);
    })
  })

  describe("verifyChallenge()", () => {
    let wallet: Wallet; // <- verifier
    let friendWallet: Wallet; // <- claimant
    
    let challengeCiphertext: Ciphertext; // generated by verifier
    let encodedChallengeCiphertext: string; // ...

    let solutionCiphertext: Ciphertext; // generated by claimant
    let encodedSolutionCiphertext: string; // ...

    beforeEach(async () => {
      wallet = new Wallet(validKeyPair.private);
      friendWallet = new Wallet(validFriendKeyPair.private); //
      
      const mockChallenge = await mockWalletGenerateChallenge(
        validKeyPair.private,
        validKeyPair.public,
        validFriendKeyPair.public
      )
      
      challengeCiphertext = mockChallenge.challengeCiphertext;
      encodedChallengeCiphertext = mockChallenge.encodedChallengeCiphertext;

      const mockSolution = await mockWalletSolveSolution(
        validFriendKeyPair.private,
        validFriendKeyPair.public,
        encodedChallengeCiphertext
      )

      solutionCiphertext = mockSolution.solutionCiphertext;
      encodedSolutionCiphertext = mockSolution.encodedSolutionCiphertext;
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

      const invalidEncodedSolutionCiphertext = await EncoderModule.encodeCiphertext(mockSolutionCiphertext);

      try {
        await wallet.verifyChallenge(invalidEncodedSolutionCiphertext);
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
      const claimantPublicKey = await wallet.verifyChallenge(encodedSolutionCiphertext);
      expect(claimantPublicKey).to.deep.equal(validFriendKeyPair.public);
    })

    it("should return null if the challenge has not been solved", async () => {
      const mockSolutionCiphertext: Ciphertext = {
        ...solutionCiphertext,
        data: challengeCiphertext.data // <-- should be solution
      }

      const invalidEncodedSolutionCiphertext = await EncoderModule.encodeCiphertext(mockSolutionCiphertext);
      const claimantPublicKey = await wallet.verifyChallenge(invalidEncodedSolutionCiphertext);
      expect(claimantPublicKey).to.be.null;
    })
  })
})