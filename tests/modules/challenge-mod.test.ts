/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { webcrypto as WebCrypto } from "crypto";
import { CHALLENGE_MAX_AGE } from "../../src/config/challenge";
import { CRYPTO_ERROR, CHALLENGE_ERROR, TEST_ERROR } from "../../src/config/messages";
import { CryptoMod } from "../../src/modules/crypto-mod";
import { Challenger, ChallengeEncoder } from "../../src/modules/challenge-mod";
import { Challenge } from "../../src/interfaces/challenge-interface";
import { PublicKey, KeyPair } from "../../src/interfaces/key-interface";

describe("Challenger Module Test Suite", () => {
  describe("Challenger", () =>{
    // verifier of the challenge
    const verifier: KeyPair = {} as unknown as KeyPair;

    // claimant to the challenge
    const claimant: KeyPair = {} as unknown as KeyPair;

    // attacker will try to solve the challenge
    const attacker: KeyPair = {} as unknown as KeyPair;

    before(async function () {
      // setup private keys
      verifier.private = await CryptoMod.generatePrivateKey();
      claimant.private = await CryptoMod.generatePrivateKey();
      attacker.private = await CryptoMod.generatePrivateKey();
      
      // setup public keys
      verifier.public = await CryptoMod.generatePublicKey({ privateKey: verifier.private });
      claimant.public = await CryptoMod.generatePublicKey({ privateKey: claimant.private });
      attacker.public = await CryptoMod.generatePublicKey({ privateKey: attacker.private });
    })
    
    describe("generateNonce()", () => {
      it("should generate a unique nonce", () => {
        const SAMPLE_SIZE = 100;
        const samples: any[] = [];
        for (let i = 0; i < SAMPLE_SIZE; i++) {
          // create nonce
          const nonce = Challenger.generateNonce();
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
        const challenge = await Challenger.generateChallenge(verifier.private, claimant.public);
        expect(challenge.verifier).to.deep.equal(verifier.public);
        expect(challenge.claimant).to.deep.equal(claimant.public);
      });
  
      it("should throw error if verifier parameter is not a valid ECDH private key", async () => {
        const invalidKey = "invalid key" as any;

        try {
          await Challenger.generateChallenge(invalidKey, claimant.public);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.INVALID_VERIFIER_PRIVATE_KEY);
        }

        try {
          await Challenger.generateChallenge(verifier.public as any, claimant.public);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.INVALID_VERIFIER_PRIVATE_KEY);
        }
      });

      it("should throw error if claimant parameter is not a valid ECDH public key", async () => {
        const invalidKey = "invalid key" as any;

        try {
          await Challenger.generateChallenge(verifier.private, invalidKey);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.INVALID_CLAIMANT_PUBLIC_KEY);
        }

        try {
          await Challenger.generateChallenge(verifier.private, claimant.private as any);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.INVALID_CLAIMANT_PUBLIC_KEY);
        }
      });
    });
  
    describe("solveChallenge()", () => {
      it("should return challenge with solution that is a hash of the nonce", async () => {
        // create challenge
        const challenge = {
          nonce: Challenger.generateNonce(),
          timestamp: Date.now(),
          verifier: verifier.public,
          claimant: claimant.public
        } as Challenge;

        // hash nonce from challenge and compare to solved challenge solution
        const nonce = challenge.nonce
        const hash = await CryptoMod.hash(nonce.toString());

        // solve challenge
        const solvedChallenge = await Challenger.solveChallenge(claimant.private, challenge);

        expect(solvedChallenge.solution).to.equal(hash);
      });

      it("should throw error if claimant parameter is not a valid ECDH private key", async () => {
        const challenge = {
          nonce: Challenger.generateNonce(),
          timestamp: Date.now(),
          verifier: verifier.public,
          claimant: claimant.public
        } as Challenge;

        try {
          await Challenger.solveChallenge("invalid private key" as any, challenge);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.INVALID_CLAIMANT_PRIVATE_KEY);
        }

        try {
          await Challenger.solveChallenge(claimant.public as any, challenge);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.INVALID_CLAIMANT_PRIVATE_KEY);
        }
      });

      it("should throw error if claimant public key is not challenge claimant", async () => {
        const challenge = {
          nonce: Challenger.generateNonce(),
          timestamp: Date.now(),
          verifier: verifier.public,
          claimant: claimant.public
        } as Challenge;

        try {
          await Challenger.solveChallenge(verifier.private, challenge);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.CLAIMANT_MISMATCH);
        }

        try {
          await Challenger.solveChallenge(attacker.private, challenge);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.CLAIMANT_MISMATCH);
        }
      });

      it("should throw error if challenge has expired [security.integrity]", async () => {
        const PAST_EXPIRATION = CHALLENGE_MAX_AGE + 1;
        
        // create challenge
        const challenge = {
          nonce: Challenger.generateNonce(),
          timestamp: Date.now() - PAST_EXPIRATION, // set timestamp to past expiration
          verifier: verifier.public,
          claimant: claimant.public
        } as Challenge;

        try {
          await Challenger.solveChallenge(claimant.private, challenge);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.EXPIRED_CHALLENGE);
        }
      });

    });
    
    describe("verifyChallenge()", () => {
      it("should return true if the solution is a hash of the nonce", async () => {
        const nonce = Challenger.generateNonce();
        const hash = await CryptoMod.hash(nonce.toString());

        const solvedChallenge = {
          nonce,
          timestamp: Date.now(),
          solution: hash,
          verifier: verifier.public,
          claimant: claimant.public
        } as Challenge;
        
        const verified = await Challenger.verifyChallenge(verifier.private, solvedChallenge);
        expect(verified).to.be.true;
      });
      
      it("should return false if solution is wrong or invalid", async () => {
        let verified: boolean;
        const stumpNonce = Challenger.generateNonce();
        const stumpHash = await CryptoMod.hash(stumpNonce.toString());

        const solvedChallenge = {
          nonce: Challenger.generateNonce(),
          timestamp: Date.now(),
          solution: stumpHash,
          verifier: verifier.public,
          claimant: claimant.public
        } as Challenge;

        verified = await Challenger.verifyChallenge(verifier.private, solvedChallenge);
        expect(verified).to.be.false;

        solvedChallenge.solution = "invalid solution";
        verified = await Challenger.verifyChallenge(verifier.private, solvedChallenge);
        expect(verified).to.be.false;
      });
      
      it("should throw error if solution has expired [security.integrity]", async () => {
        const PAST_EXPIRATION = CHALLENGE_MAX_AGE + 1;
        // create challenge
        const solvedChallenge = {
          nonce: Challenger.generateNonce(),
          timestamp: Date.now() - PAST_EXPIRATION, // set timestamp to past expiration
          solution: "invalid solution",
          verifier: verifier.public,
          claimant: claimant.public
        } as Challenge;
        
        try {
          await Challenger.verifyChallenge(verifier.private, solvedChallenge);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.EXPIRED_CHALLENGE);
        }
      });

      it("should throw error if verifier public key is not challenge's verifier", async () => {
        // create challenge
        const solvedChallenge = {
          nonce: Challenger.generateNonce(),
          timestamp: Date.now(),
          solution: "invalid solution",
          verifier: verifier.public,
          claimant: claimant.public
        } as Challenge;

        try {
          await Challenger.verifyChallenge(attacker.private, solvedChallenge);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.VERIFIER_MISMATCH);
        }

        try {
          await Challenger.verifyChallenge(claimant.private, solvedChallenge);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(CHALLENGE_ERROR.VERIFIER_MISMATCH);
        }
      });

    });
  })

  describe("ChallengeEncoder", () => {
    describe("Public Key", () => {
      let publicKey: PublicKey;

      before(async () => {
        publicKey = await CryptoMod.generatePublicKey({
          privateKey: await CryptoMod.generatePrivateKey()
        })
      })

      describe("publicKeyToString()", () => {
        it("should convert a public key to a string", async () => {
          const publicKeyString = await ChallengeEncoder.publicKeyToString(publicKey);

          const publicKeyObject = JSON.parse(publicKeyString);
          expect(publicKeyObject).to.have.property("type");
          expect(publicKeyObject.type).to.equal(publicKey.type);

          if (publicKey.domain) {
            expect(publicKeyObject).to.have.property("domain");
            expect(publicKeyObject.domain).to.equal(publicKey.domain);
          }

          expect(publicKeyObject).to.have.property("crypto");
          // check that crypto is the base64 encoded string of the crypto object
          const spki = await WebCrypto.subtle.exportKey("spki", publicKey.crypto);
          const spkiBase64 = Buffer.from(spki).toString("base64");
          expect(publicKeyObject.crypto).to.equal(spkiBase64);
        })

        it("should throw an error if the public key is invalid", async () => {
          const secretKey = await CryptoMod.generateKey() as any;
          const invalidKey = "invalid key" as any;

          try {
            await ChallengeEncoder.publicKeyToString(secretKey);
            expect.fail(TEST_ERROR.DID_NOT_THROW)
          } catch (e) {
            const error = e as Error;
            expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_PUBLIC_KEY);
          }

          try {
            await ChallengeEncoder.publicKeyToString(invalidKey);
            expect.fail(TEST_ERROR.DID_NOT_THROW)
          } catch (e) {
            const error = e as Error;
            expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_PUBLIC_KEY);
          }
        });
      })

      describe("stringToPublicKey()", () => {
        it("should convert a string to a public key", async () => {
          // convert the public key to a string
          const publicKeyString = await ChallengeEncoder.publicKeyToString(publicKey);

          // convert the string back to a public key
          const publicKeyObject = await ChallengeEncoder.stringToPublicKey(publicKeyString);

          if (publicKey.domain) {
            expect(publicKeyObject).to.have.property("domain");
            expect(publicKeyObject.domain).to.equal(publicKey.domain);
          }

          expect(publicKeyObject).to.have.property("type");
          expect(publicKeyObject.type).to.equal(publicKey.type);

          expect(publicKeyObject).to.have.property("crypto");
          expect(publicKeyObject.crypto).to.deep.equal(publicKey.crypto);
        });

        it("should throw an error if the string is an invalid public key", async () => {
          const invalidPublicKeyString = "invalid public key string";

          try {
            await ChallengeEncoder.stringToPublicKey(invalidPublicKeyString);
            expect.fail(TEST_ERROR.DID_NOT_THROW)
          } catch (e) {
            const error = e as Error;
            expect(error.message).to.equal(CRYPTO_ERROR.ASYMMETRIC.INVALID_PUBLIC_KEY);
          }
        });
      })
    })

    describe("Challenge", () => {
      let nonce: Uint8Array;
      let verifierPublicKey: PublicKey;
      let claimantPublicKey: PublicKey;
      let challenge: Challenge;

      before(async () => {
        // set random number
        nonce = Challenger.generateNonce();
        // set verifier's public key
        verifierPublicKey = await CryptoMod.generatePublicKey({
          privateKey: await CryptoMod.generatePrivateKey()
        })
        // set claimant's crypto key
        claimantPublicKey = await CryptoMod.generatePublicKey({
          privateKey: await CryptoMod.generatePrivateKey()
        })
        // set challenge
        challenge = {
          nonce,
          timestamp: Date.now(),
          verifier: verifierPublicKey,
          claimant: claimantPublicKey
        } as Challenge;
      })

      describe("challengeToString()", () => {
        it("should convert a challenge to the <nonce>::<timestamp>::<verifier>::<claimant>::<solution> format", async () => {
          const challengeWithSolution = {
            ...challenge,
            solution: "test solution"
          } as Challenge;

          const challengeString = await ChallengeEncoder.challengeToString(challengeWithSolution); // <nonce>::<timestamp>::<verifier>
          const challengeArray = challengeString.split("::");

          const isRightLength = challengeArray.length === 4 || challengeArray.length === 5;

          expect(isRightLength).to.be.true;
          expect(challengeArray[0]).to.equal(nonce.toString());
          expect(challengeArray[1]).to.equal(challenge.timestamp.toString());

          const verifierPublicKeyString = await ChallengeEncoder.publicKeyToString(challenge.verifier);
          expect(challengeArray[2]).to.equal(verifierPublicKeyString);

          const claimantPublicKeyString = await ChallengeEncoder.publicKeyToString(challenge.claimant);
          expect(challengeArray[3]).to.equal(claimantPublicKeyString);
        })

        it("should handle a challenge with no solution", async () => {
          const challengeString = await ChallengeEncoder.challengeToString(challenge); // <nonce>::<timestamp>::<verifier>
          const challengeArray = challengeString.split("::");

          expect(challengeArray.length).to.equal(4);
          expect(challengeArray[0]).to.equal(nonce.toString());
          expect(challengeArray[1]).to.equal(challenge.timestamp.toString());

          const verifierPublicKeyString = await ChallengeEncoder.publicKeyToString(challenge.verifier);
          expect(challengeArray[2]).to.equal(verifierPublicKeyString);

          const claimantPublicKeyString = await ChallengeEncoder.publicKeyToString(challenge.claimant);
          expect(challengeArray[3]).to.equal(claimantPublicKeyString);
        });

        /**
         * @todo
         * 1. should throw an error if invalid nonce is not a Uint8Array
         * 2. should throw an error if invalid timestamp is not a number
         * 3. should throw an error if invalid verifier is not a public key object
         */
        it("should throw an error if invalid challenge is passed")
      })

      describe("stringToChallenge()", () => {
        it("should convert format <nonce>::<timestamp>::<verifier>::<claimant>::<solution> to a challenge object", async () => {
          const challengeWithSolution = {
            ...challenge,
            solution: "test solution"
          } as Challenge;

          // convert the challenge to a string
          const challengeString = await ChallengeEncoder.challengeToString(challengeWithSolution); // <nonce>::<timestamp>::<verifier>::<claimant>::<solution>

          // convert the string back to a challenge object
          const challengeObject = await ChallengeEncoder.stringToChallenge(challengeString);
          
          expect(challengeObject.nonce).to.deep.equal(challenge.nonce);
          expect(challengeObject.timestamp).to.equal(challenge.timestamp);
          expect(challengeObject.verifier).to.deep.equal(challenge.verifier);
          expect(challengeObject.claimant).to.deep.equal(challenge.claimant);
          expect(challengeObject.solution).to.equal(challengeWithSolution.solution);
        })

        it("should handle a challenge with no solution", async () => {
          // convert the challenge to a string
          const challengeString = await ChallengeEncoder.challengeToString(challenge); // <nonce>::<timestamp>::<verifier>::<claimant>::<solution>

          // convert the string back to a challenge object
          const challengeObject = await ChallengeEncoder.stringToChallenge(challengeString);

          expect(challengeObject.nonce).to.deep.equal(challenge.nonce);
          expect(challengeObject.timestamp).to.equal(challenge.timestamp);
          expect(challengeObject.verifier).to.deep.equal(challenge.verifier);
          expect(challengeObject.claimant).to.deep.equal(challenge.claimant);
        });

        /**
         * @todo
         * 1. should throw an error if invalid nonce is not a Uint8Array
         * 2. should throw an error if invalid timestamp is not a number
         * 3. should throw an error if invalid verifier is not a public key object
         */
        it("should throw an error if invalid challenge string is passed")
      })
    });
  })
});