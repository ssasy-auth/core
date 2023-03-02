/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { TEST_ERROR } from "../../config/test";
import { Challenge } from "../../src/interfaces/challenge-interface";
import { PublicKey } from "../../src/interfaces/key-interface";
import { KeyModule } from "../../src/modules/key-mod";
import { ChallengeModule } from "../../src/modules/challenge-mod";
import { EncoderModule, ENCODER_ERROR_MESSAGE } from "../../src/modules/encoder-mod";

describe("EncoderModule Test Suite", () => {
  describe("Key", () => {
    let publicKey: PublicKey;

    before(async () => {
      publicKey = await KeyModule.generatePublicKey({
        privateKey: await KeyModule.generatePrivateKey()
      })
    })

    describe("publicKeyToString()", () => {
      it("should convert a public key to a string", async () => {
        const publicKeyString = await EncoderModule.key.publicKeyToString(publicKey);

        const publicKeyObject = JSON.parse(publicKeyString);
        expect(publicKeyObject).to.have.property("type");
        expect(publicKeyObject.type).to.equal(publicKey.type);

        if (publicKey.domain) {
          expect(publicKeyObject).to.have.property("domain");
          expect(publicKeyObject.domain).to.equal(publicKey.domain);
        }

        expect(publicKeyObject).to.have.property("crypto");
        // check that crypto is the base64 encoded string of the crypto object
        const rawKey = await KeyModule.exportKey(publicKey);
        expect(publicKeyObject.crypto).to.deep.equal(rawKey.crypto);
      })

      it("should throw an error if the public key is invalid", async () => {
        const secretKey = await KeyModule.generateKey() as any;
        const invalidKey = "invalid key" as any;

        try {
          await EncoderModule.key.publicKeyToString(secretKey);
          expect.fail(TEST_ERROR.DID_NOT_THROW)
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(ENCODER_ERROR_MESSAGE.KEY_NOT_SUPPORTED);
        }

        try {
          await EncoderModule.key.publicKeyToString(invalidKey);
          expect.fail(TEST_ERROR.DID_NOT_THROW)
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(ENCODER_ERROR_MESSAGE.KEY_NOT_SUPPORTED);
        }
      });
    })

    describe("stringToPublicKey()", () => {
      it("should convert a string to a public key", async () => {
        // convert the public key to a string
        const publicKeyString = await EncoderModule.key.publicKeyToString(publicKey);

        // convert the string back to a public key
        const publicKeyObject = await EncoderModule.key.stringToPublicKey(publicKeyString);

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
          await EncoderModule.key.stringToPublicKey(invalidPublicKeyString);
          expect.fail(TEST_ERROR.DID_NOT_THROW)
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(ENCODER_ERROR_MESSAGE.INVALID_ENCODING);
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
      nonce = ChallengeModule.generateNonce();
      // set verifier's public key
      verifierPublicKey = await KeyModule.generatePublicKey({
        privateKey: await KeyModule.generatePrivateKey()
      })
      // set claimant's crypto key
      claimantPublicKey = await KeyModule.generatePublicKey({
        privateKey: await KeyModule.generatePrivateKey()
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

        const challengeString = await EncoderModule.challenge.challengeToString(challengeWithSolution); // <nonce>::<timestamp>::<verifier>
        const challengeArray = challengeString.split("::");

        const isRightLength = challengeArray.length === 4 || challengeArray.length === 5;

        expect(isRightLength).to.be.true;
        expect(challengeArray[0]).to.equal(nonce.toString());
        expect(challengeArray[1]).to.equal(challenge.timestamp.toString());

        const verifierPublicKeyString = await EncoderModule.key.publicKeyToString(challenge.verifier);
        expect(challengeArray[2]).to.equal(verifierPublicKeyString);

        const claimantPublicKeyString = await EncoderModule.key.publicKeyToString(challenge.claimant);
        expect(challengeArray[3]).to.equal(claimantPublicKeyString);
      })

      it("should handle a challenge with no solution", async () => {
        const challengeString = await EncoderModule.challenge.challengeToString(challenge); // <nonce>::<timestamp>::<verifier>
        const challengeArray = challengeString.split("::");

        expect(challengeArray.length).to.equal(4);
        expect(challengeArray[0]).to.equal(nonce.toString());
        expect(challengeArray[1]).to.equal(challenge.timestamp.toString());

        const verifierPublicKeyString = await EncoderModule.key.publicKeyToString(challenge.verifier);
        expect(challengeArray[2]).to.equal(verifierPublicKeyString);

        const claimantPublicKeyString = await EncoderModule.key.publicKeyToString(challenge.claimant);
        expect(challengeArray[3]).to.equal(claimantPublicKeyString);
      });

      /**
       * @todo
       * 1. should throw an error if invalid nonce is not a Uint8Array
       * 2. should throw an error if invalid timestamp is not a number
       * 3. should throw an error if invalid verifier is not a public key object
       */
      it("should throw an error if invalid challenge is passed", async () => {
        let challengeCopy: Challenge;

        try {
          challengeCopy = { ...challenge };
          challengeCopy.nonce = "invalid nonce" as any;
          await EncoderModule.challenge.challengeToString(challengeCopy);
          expect.fail(TEST_ERROR.DID_NOT_THROW)
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE);
        }

        try {
          challengeCopy = { ...challenge };
          challengeCopy.timestamp = "invalid timestamp" as any;
          await EncoderModule.challenge.challengeToString(challengeCopy);
          expect.fail(TEST_ERROR.DID_NOT_THROW)
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE);
        }

        try {
          challengeCopy = { ...challenge };
          challengeCopy.timestamp = "invalid timestamp" as any;
          await EncoderModule.challenge.challengeToString(challengeCopy);
          expect.fail(TEST_ERROR.DID_NOT_THROW)
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE);
        }

        try {
          challengeCopy = { ...challenge };
          challengeCopy.claimant = "invalid claimant" as any;
          await EncoderModule.challenge.challengeToString(challengeCopy);
          expect.fail(TEST_ERROR.DID_NOT_THROW)
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE);
        }
      })
    })

    describe("stringToChallenge()", () => {
      it("should convert format <nonce>::<timestamp>::<verifier>::<claimant>::<solution> to a challenge object", async () => {
        const challengeWithSolution = {
          ...challenge,
          solution: "test solution"
        } as Challenge;

        // convert the challenge to a string
        const challengeString = await EncoderModule.challenge.challengeToString(challengeWithSolution); // <nonce>::<timestamp>::<verifier>::<claimant>::<solution>

        // convert the string back to a challenge object
        const challengeObject = await EncoderModule.challenge.stringToChallenge(challengeString);

        expect(challengeObject.nonce).to.deep.equal(challenge.nonce);
        expect(challengeObject.timestamp).to.equal(challenge.timestamp);
        expect(challengeObject.verifier).to.deep.equal(challenge.verifier);
        expect(challengeObject.claimant).to.deep.equal(challenge.claimant);
        expect(challengeObject.solution).to.equal(challengeWithSolution.solution);
      })

      it("should handle a challenge with no solution", async () => {
        // convert the challenge to a string
        const challengeString = await EncoderModule.challenge.challengeToString(challenge); // <nonce>::<timestamp>::<verifier>::<claimant>::<solution>

        // convert the string back to a challenge object
        const challengeObject = await EncoderModule.challenge.stringToChallenge(challengeString);

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
      it("should throw an error if invalid challenge string is passed", async () => {
        
        try {
          await EncoderModule.challenge.stringToChallenge(`invalid-nonce::${challenge.timestamp}::${challenge.verifier}::${challenge.claimant}::${challenge.solution}`);
          expect.fail(TEST_ERROR.DID_NOT_THROW)
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
        }

        try {
          await EncoderModule.challenge.stringToChallenge(`${challenge.nonce}::invalid-timestamp::${challenge.verifier}::${challenge.claimant}::${challenge.solution}`);
          expect.fail(TEST_ERROR.DID_NOT_THROW)
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
        }

        try {
          await EncoderModule.challenge.stringToChallenge(`${challenge.nonce}::${challenge.timestamp}::${challenge.verifier}::${challenge.claimant}::${challenge.solution}`);
          expect.fail(TEST_ERROR.DID_NOT_THROW)
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
        }
      })
    })
  });
})