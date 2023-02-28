import { webcrypto as WebCrypto } from "crypto";
import { CRYPTO_CONFIG } from "../config/algorithm";
import { CHALLENGE_MAX_AGE } from "../config/challenge";
import { CHALLENGE_ERROR, CRYPTO_ERROR } from "../config/messages";
import { Challenge } from "../interfaces/challenge-interface";
import { KeyType, PrivateKey, PublicKey } from "../interfaces/key-interface";
import { CryptoMod, KeyHelper } from "./crypto-mod";

/**
 * Provides operations for formatting keys, challenges and solutions to and from strings
 */
export const ChallengeEncoder = {
  /**
     * Returns a stringified JSON representation of the public key
     *
     * @param key - the public key to convert to a string
     * @returns string representation of the public key
     * */
  publicKeyToString: async (key: PublicKey): Promise<string> => {
    if(!key) {
      throw new Error(CHALLENGE_ERROR.MISSING_KEY);
    }

    if (!KeyHelper.isAsymmetricKey(key) || key.type !== KeyType.PublicKey) {
      throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_PUBLIC_KEY);
    }

    // encode the CryptoKey as a X.509 SubjectPublicKeyInfo (SPKI) PEM
    const spki = await WebCrypto.subtle.exportKey("spki", key.crypto);

    // convert DER-encoded public key to a base64 string
    const spkiBase64 = Buffer.from(spki).toString("base64");

    return JSON.stringify({
      ...key,
      crypto: spkiBase64
    })
  },
  /**
   * Returns a public key from a stringyfied JSON representation of the public key
   *
   * @param key - the string representation of the public key
   * @returns the public key
   * */
  stringToPublicKey: async (key: string): Promise<PublicKey> => {
    if(!key) {
      throw new Error(CHALLENGE_ERROR.MISSING_KEY);
    }

    let publicKey: PublicKey;
    let cryptoKey: WebCrypto.CryptoKey;

    try {
      publicKey = JSON.parse(key);
    } catch (error) {
      if (error instanceof Error && error.name === "SyntaxError") {
        throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_PUBLIC_KEY);
      }

      throw error;
    }

    try {
      // convert the base64 encoded string to a DER-encoded public key
      const spki = Buffer.from(publicKey.crypto as unknown as string, "base64");

      cryptoKey = await WebCrypto.subtle.importKey(
        "spki",
        spki,
        CRYPTO_CONFIG.ASYMMETRIC.algorithm,
        CRYPTO_CONFIG.ASYMMETRIC.exportable,
        CRYPTO_CONFIG.ASYMMETRIC.usages
      );
    } catch (error) {
      if (error instanceof Error && error.message === "TypeError") {
        throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_PUBLIC_KEY);
      }
      throw error;
    }

    return {
      type: publicKey.type,
      domain: publicKey.domain,
      crypto: cryptoKey
    }
  },

  /**
     * Returns a string representation of the challenge.
     * String representation is in the format: `<nonce>::<timestamp>::<verifier>::<claimant>::<solution>`
     *
     * @param challenge - the challenge to convert to a string
     * @returns challenge string
     * */
  challengeToString: async (challenge: Challenge): Promise<string> => {
    const { nonce, timestamp, verifier, claimant } = challenge;

    // convert nonce to string
    const nonceString = nonce.toString();

    // convert timestamp to string
    const timestampString = timestamp.toString();

    // convert verifier's public key to string
    const verifierString = await ChallengeEncoder.publicKeyToString(verifier);

    // convert claimant's public key to string
    const claimantString = await ChallengeEncoder.publicKeyToString(claimant);

    // convert solution to string
    const solutionString = challenge.solution
      ? "::" + challenge.solution
      : "";

    return `${nonceString}::${timestampString}::${verifierString}::${claimantString}${solutionString}`
  },

  /**
   * Returns a challenge object from a string representation of a challenge
   * 
   * @param challenge - the string representation of the challenge
   * @returns challenge object
   * */
  stringToChallenge: async (challenge: string): Promise<Challenge> => {
    const [ nonce, timestamp, verifier, claimant, solution ] = challenge.split("::");

    // convert nonce.toString() back to Uint8Array
    const nonceUint8Array = new Uint8Array(nonce.split(",").map(Number));

    // convert timestamp back to number
    const timestampNumber = Number(timestamp);

    // convert verifier's public key back to CryptoKey
    const verifierCryptoKey = await ChallengeEncoder.stringToPublicKey(verifier);

    // convert claimant's public key back to CryptoKey
    const claimantCryptoKey = await ChallengeEncoder.stringToPublicKey(claimant);

    // convert solution back to string
    const solutionString = solution
      ? solution
      : undefined;

    return {
      nonce: nonceUint8Array,
      timestamp: timestampNumber,
      verifier: verifierCryptoKey,
      claimant: claimantCryptoKey,
      solution: solutionString
    }
  }
};

/**
 * Returns true if the challenge has expired
 * 
 * @param timestamp - the timestamp of the challenge
 * @returns boolean
 */
function ChallengeHasExpired(timestamp: number): boolean {
  const now = Date.now();
  return now - timestamp > CHALLENGE_MAX_AGE;
}

/**
 * Functions for authenticating ownership of a public key
 */
export const Challenger = {
  /**
	 * Returns a random nonce
	 * @returns nonce
	 */
  generateNonce(): Uint8Array {
    return WebCrypto.getRandomValues(new Uint8Array(16));
  },

  /**
	 * Returns a challenge object
	 *
	 * The challenge is a combination of a nonce, timestamp, and the verifier's public key such that the
	 * string format looks like this: <nonce>::<timestamp>::<verifier>
	 *
	 * @param verifier - the user who created the challenge
	 * @param claimant - the user who will solve the challenge
	 */
  async generateChallenge(verifier: PrivateKey, claimant: PublicKey ): Promise<Challenge> {
    if(!verifier || !claimant) {
      throw new Error(CHALLENGE_ERROR.MISSING_KEY);
    }

    if(!KeyHelper.isAsymmetricKey(verifier) || verifier.type !== KeyType.PrivateKey) {
      throw new Error(CHALLENGE_ERROR.INVALID_VERIFIER_PRIVATE_KEY);
    }

    if(!KeyHelper.isAsymmetricKey(claimant) || claimant.type !== KeyType.PublicKey) {
      throw new Error(CHALLENGE_ERROR.INVALID_CLAIMANT_PUBLIC_KEY);
    }

    // generate verifier public key
    const verifierPublicKey = await CryptoMod.generatePublicKey({ privateKey: verifier })

    // create challenge
    return {
      nonce: Challenger.generateNonce(),
      timestamp: Date.now(),
      verifier: verifierPublicKey,
      claimant: claimant
    } as Challenge;
  },

  /**
	 * Returns a challenge with populated solution property. 
   * The solution should be a base64 encoded string of the hash of the nonce.
	 *
	 * @param claimant - the user who will solve the challenge
	 * @param challengeString - the challenge to solve
	 */
  async solveChallenge(claimant: PrivateKey, challenge: Challenge): Promise<Challenge> {
    if(!claimant) {
      throw new Error(CHALLENGE_ERROR.MISSING_KEY);
    }

    if (!challenge) {
      throw new Error(CHALLENGE_ERROR.MISSING_CHALLENGE);
    }

    if(!KeyHelper.isAsymmetricKey(claimant) || claimant.type !== KeyType.PrivateKey) {
      throw new Error(CHALLENGE_ERROR.INVALID_CLAIMANT_PRIVATE_KEY);
    }

    const claimantPublicKey = await CryptoMod.generatePublicKey({ privateKey: claimant });
    if (! await CryptoMod.isSameKey(claimantPublicKey, challenge.claimant)) {
      throw new Error(CHALLENGE_ERROR.CLAIMANT_MISMATCH);
    }

    if(ChallengeHasExpired(challenge.timestamp)) {
      throw new Error(CHALLENGE_ERROR.EXPIRED_CHALLENGE);
    }

    // create solution = hash(nonce)
    challenge.solution = await CryptoMod.hash(challenge.nonce.toString());

    return challenge;
  },

  /**
	 * Returns true if the challenge was solved correctly.
	 * To be solved correctly, the solution property of the challenge must be a hash of the nonce in base64 format.
	 *
	 * @param verifier - the user who created the challenge
	 * @param challenge - the challenge to verify
	 */
  async verifyChallenge(verifier: PrivateKey, challenge: Challenge): Promise<boolean> {
    if(!verifier) {
      throw new Error(CHALLENGE_ERROR.MISSING_KEY);
    }
    
    if(!challenge) {
      throw new Error(CHALLENGE_ERROR.MISSING_CHALLENGE);
    }

    if(!KeyHelper.isAsymmetricKey(verifier) || verifier.type !== KeyType.PrivateKey) {
      throw new Error(CHALLENGE_ERROR.INVALID_VERIFIER_PRIVATE_KEY);
    }

    const verifierPublicKey = await CryptoMod.generatePublicKey({ privateKey: verifier });
    if(!await CryptoMod.isSameKey(verifierPublicKey, challenge.verifier)) {
      throw new Error(CHALLENGE_ERROR.VERIFIER_MISMATCH);
    }

    if (ChallengeHasExpired(challenge.timestamp)) {
      throw new Error(CHALLENGE_ERROR.EXPIRED_CHALLENGE);
    }

    if(!challenge.solution) {
      throw new Error(CHALLENGE_ERROR.MISSING_SOLUTION);
    }

    // verify that the solution is a hash of nonce
    const hashedNonce = await CryptoMod.hash(challenge.nonce.toString());

    return hashedNonce === challenge.solution;
  }
};
