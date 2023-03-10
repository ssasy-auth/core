/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { TEST_ERROR } from "../config";
import { CHALLENGE_MAX_AGE } from "../../src/config";
import { BufferLib } from "../../src/utils";
import {
  KeyModule, CryptoModule, ChallengeModule, CHALLENGE_ERROR_MESSAGE 
} from "../../src/modules";
import type { KeyPair } from "../../src/interfaces/key-interface";
import type { Challenge } from "../../src/interfaces";

describe("[ChallengeModule Module Test Suite]", () => {
  // verifier of the challenge
  const verifier: KeyPair = {
  } as unknown as KeyPair;

  // claimant to the challenge
  const claimant: KeyPair = {
  } as unknown as KeyPair;

  // attacker will try to solve the challenge
  const attacker: KeyPair = {
  } as unknown as KeyPair;

  // nonce
  let validNonce: Uint8Array;
  let validNonceString: string;

  before(async function () {
    // setup private keys
    verifier.private = await KeyModule.generatePrivateKey();
    claimant.private = await KeyModule.generatePrivateKey();
    attacker.private = await KeyModule.generatePrivateKey();
      
    // setup public keys
    verifier.public = await KeyModule.generatePublicKey({
      privateKey: verifier.private 
    });
    claimant.public = await KeyModule.generatePublicKey({
      privateKey: claimant.private 
    });
    attacker.public = await KeyModule.generatePublicKey({
      privateKey: attacker.private 
    });

    // generate nonce
    validNonce = ChallengeModule.generateNonce();
    validNonceString = BufferLib.toString(validNonce, "base64");
  })
    
  describe("generateNonce()", () => {
    it("should generate a unique nonce", () => {
      const SAMPLE_SIZE = 100;
      const samples: any[] = [];
      for (let i = 0; i < SAMPLE_SIZE; i++) {
        // create nonce
        const nonce = ChallengeModule.generateNonce();
        // check current sample for any identical nonces
        for (let x = 0; x < i; x++) {
          const currNonce = samples[x] as Uint8Array;
          expect(nonce).to.not.deep.equal(currNonce);
        }
        // add nonce to samples
        samples.push(nonce)
      }
    });
  });
  
  describe("generateChallenge()", () => {
    it("should return challenge with valid sender and recipient public keys", async () => {
      const challenge = await ChallengeModule.generateChallenge(verifier.private, claimant.public);
      expect(challenge.verifier).to.deep.equal(verifier.public);
      expect(challenge.claimant).to.deep.equal(claimant.public);
    });
  
    it("should throw error if verifier parameter is not a valid ECDH private key", async () => {
      const invalidKey = "invalid key" as any;

      try {
        await ChallengeModule.generateChallenge(invalidKey, claimant.public);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.INVALID_VERIFIER_PRIVATE_KEY);
      }

      try {
        await ChallengeModule.generateChallenge(verifier.public as any, claimant.public);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.INVALID_VERIFIER_PRIVATE_KEY);
      }
    });

    it("should throw error if claimant parameter is not a valid ECDH public key", async () => {
      const invalidKey = "invalid key" as any;

      try {
        await ChallengeModule.generateChallenge(verifier.private, invalidKey);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.INVALID_CLAIMANT_PUBLIC_KEY);
      }

      try {
        await ChallengeModule.generateChallenge(verifier.private, claimant.private as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.INVALID_CLAIMANT_PUBLIC_KEY);
      }
    });
  });
  
  describe("solveChallenge()", () => {
    it("should return challenge with solution that is a hash of the nonce", async () => {
      // create challenge
      const challenge = {
        nonce: validNonceString,
        timestamp: Date.now(),
        verifier: verifier.public,
        claimant: claimant.public
      } as Challenge;

      // hash nonce from challenge and compare to solved challenge solution
      const nonce = challenge.nonce
      const hash = await CryptoModule.hash(nonce.toString());

      // solve challenge
      const solvedChallenge = await ChallengeModule.solveChallenge(claimant.private, challenge);

      expect(solvedChallenge.solution).to.equal(hash);
    });

    it("should throw error if claimant parameter is not a valid ECDH private key", async () => {
      const challenge = {
        nonce: validNonceString,
        timestamp: Date.now(),
        verifier: verifier.public,
        claimant: claimant.public
      } as Challenge;

      try {
        await ChallengeModule.solveChallenge("invalid private key" as any, challenge);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.INVALID_CLAIMANT_PRIVATE_KEY);
      }

      try {
        await ChallengeModule.solveChallenge(claimant.public as any, challenge);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.INVALID_CLAIMANT_PRIVATE_KEY);
      }
    });

    it("should throw error if claimant public key is not challenge claimant", async () => {
      const challenge = {
        nonce: validNonceString,
        timestamp: Date.now(),
        verifier: verifier.public,
        claimant: claimant.public
      } as Challenge;

      try {
        await ChallengeModule.solveChallenge(verifier.private, challenge);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.CLAIMANT_MISMATCH);
      }

      try {
        await ChallengeModule.solveChallenge(attacker.private, challenge);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.CLAIMANT_MISMATCH);
      }
    });

    it("should throw error if challenge has expired [security.integrity]", async () => {
      const PAST_EXPIRATION = CHALLENGE_MAX_AGE + 1;
        
      // create challenge
      const challenge = {
        nonce: validNonceString,
        timestamp: Date.now() - PAST_EXPIRATION, // set timestamp to past expiration
        verifier: verifier.public,
        claimant: claimant.public
      } as Challenge;

      try {
        await ChallengeModule.solveChallenge(claimant.private, challenge);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.EXPIRED_CHALLENGE);
      }
    });

  });
    
  describe("verifyChallenge()", () => {
    it("should return true if the solution is a hash of the nonce", async () => {
      const nonce = ChallengeModule.generateNonce();
      const nonceString = BufferLib.toString(nonce, "base64");
      const hash = await CryptoModule.hash(nonceString);

      const solvedChallenge = {
        nonce: nonceString,
        timestamp: Date.now(),
        solution: hash,
        verifier: verifier.public,
        claimant: claimant.public
      } as Challenge;
        
      const verified = await ChallengeModule.verifyChallenge(verifier.private, solvedChallenge);
      expect(verified).to.be.true;
    });
      
    it("should return false if solution is wrong or invalid", async () => {
      let verified: boolean;
      const stumpNonce = ChallengeModule.generateNonce();
      const stumpHash = await CryptoModule.hash(stumpNonce.toString());

      const solvedChallenge = {
        nonce: validNonceString,
        timestamp: Date.now(),
        solution: stumpHash,
        verifier: verifier.public,
        claimant: claimant.public
      } as Challenge;

      verified = await ChallengeModule.verifyChallenge(verifier.private, solvedChallenge);
      expect(verified).to.be.false;

      solvedChallenge.solution = "invalid solution";
      verified = await ChallengeModule.verifyChallenge(verifier.private, solvedChallenge);
      expect(verified).to.be.false;
    });
      
    it("should throw error if solution has expired [security.integrity]", async () => {
      const PAST_EXPIRATION = CHALLENGE_MAX_AGE + 1;
      // create challenge
      const solvedChallenge = {
        nonce: validNonceString,
        timestamp: Date.now() - PAST_EXPIRATION, // set timestamp to past expiration
        solution: "invalid solution",
        verifier: verifier.public,
        claimant: claimant.public
      } as Challenge;
        
      try {
        await ChallengeModule.verifyChallenge(verifier.private, solvedChallenge);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.EXPIRED_CHALLENGE);
      }
    });

    it("should throw error if verifier public key is not challenge's verifier", async () => {
      // create challenge
      const solvedChallenge = {
        nonce: validNonceString,
        timestamp: Date.now(),
        solution: "invalid solution",
        verifier: verifier.public,
        claimant: claimant.public
      } as Challenge;

      try {
        await ChallengeModule.verifyChallenge(attacker.private, solvedChallenge);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.VERIFIER_MISMATCH);
      }

      try {
        await ChallengeModule.verifyChallenge(claimant.private, solvedChallenge);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(CHALLENGE_ERROR_MESSAGE.VERIFIER_MISMATCH);
      }
    });
  });
});