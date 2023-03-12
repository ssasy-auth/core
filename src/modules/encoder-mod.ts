import { KeyType } from "../interfaces";
import { KeyModule, KeyChecker } from "./key-mod";
import { ChallengeChecker } from "./challenge-mod";
import type {
  PublicKey, RawKey , GenericKey, Challenge
} from "../interfaces";

export const ENCODER_ERROR_MESSAGE = {
  MISSING_KEY: "Key is missing",
  KEY_NOT_SUPPORTED: "Key is not supported",
  INVALID_ENCODING: "Encoding is invalid",
  INVALID_CHALLENGE: "Challenge is invalid",
  INVALID_CHALLENGE_STRING: "Challenge string is invalid"
};

/**
 * Returns true if key is a valid asymmetric **public** key
 * 
 * @param key - the key to check
 * @returns boolean
 */
function isPublicKey(key: GenericKey): boolean {
  return KeyChecker.isAsymmetricKey(key) && key.type === KeyType.PublicKey;
}

/**
 * Operations for encoding objects for transport.
 */
export const EncoderModule = {
  /**
	 * Returns a string representation of the key
	 *
	 * @param key - key
	 * @returns string
	 * */
  encodeKey: async (key: GenericKey): Promise<string> => {
    let rawKey: RawKey;

    if (!KeyChecker.isKey(key)) {
      throw new Error(ENCODER_ERROR_MESSAGE.KEY_NOT_SUPPORTED);
    }

    if(KeyChecker.isRawKey(key)) {
      rawKey = key as RawKey;
    } else {
      rawKey = await KeyModule.exportKey(key);
    }

    const keyString = JSON.stringify(rawKey);

    // TODO: convert string (utf-8) to buffer (uint8array)

    // TODO: convert buffer to base64 string
    return keyString
  },
  /**
	 * Returns a key from a stringyfied JSON representation of the key
	 *
	 * @param key - the string representation of the key
	 * @returns key
	 * */
  decodeKey: async (string: string): Promise<GenericKey> => {
    if (!string) {
      throw new Error(ENCODER_ERROR_MESSAGE.MISSING_KEY);
    }

    // TODO: convert base64 string to buffer

    // TODO: convert buffer to string (utf-8)

    let rawKey: RawKey;

    try {
      rawKey = JSON.parse(string);
    } catch (error) {
      if (error instanceof Error && error.name === "SyntaxError") {
        throw new Error(ENCODER_ERROR_MESSAGE.INVALID_ENCODING);
      }

      throw `Error parsing key: ${error}`
    }

    return await KeyModule.importKey(rawKey) as PublicKey;
  },
  /**
	 * Returns a string representation of the challenge.
	 * String representation is in the format: `<nonce>::<timestamp>::<verifier>::<claimant>::<solution>`
	 *
	 * @param challenge - the challenge to convert to a string
	 * @returns encoded challenge
	 * */
  encodeChallenge: async (challenge: Challenge): Promise<string> => {
    if (!ChallengeChecker.isChallenge(challenge)) {
      throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE);
    }

    const { nonce, timestamp, verifier, claimant, solution } = challenge;

    // convert nonce to string
    const nonceString = nonce;

    // convert timestamp to string
    const timestampString = timestamp.toString();

    // convert verifier's public key to string
    const verifierString = await EncoderModule.encodeKey(verifier);

    // convert claimant's public key to string
    const claimantString = await EncoderModule.encodeKey(claimant);

    // convert solution to string
    const solutionString = solution ? "::" + solution : "";

    return `${nonceString}::${timestampString}::${verifierString}::${claimantString}${solutionString}`;
  },

  /**
	 * Returns a challenge object from a string representation of a challenge
	 *
	 * @param challenge - the string representation of the challenge
	 * @returns challenge
	 * */
  decodeChallenge: async (challenge: string): Promise<Challenge> => {
    const [ nonce, timestamp, verifier, claimant, solution ] =			challenge.split("::");

    let nonceString: string;
    let timestampNumber: number;
    let verifierCryptoKey: PublicKey;
    let claimantCryptoKey: PublicKey;
    let solutionString: string | undefined;

    try {
      // convert nonce.toString() back to Uint8Array
      nonceString = nonce

      // convert timestamp back to number
      timestampNumber = Number(timestamp);

      // convert verifier's public key back to CryptoKey
      const decodedVerifierKey = await EncoderModule.decodeKey(verifier);

      if(!isPublicKey(decodedVerifierKey)) {
        throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
      }

      verifierCryptoKey = decodedVerifierKey as PublicKey;

      // convert claimant's public key back to CryptoKey
      const decodedClaimantKey = await EncoderModule.decodeKey(claimant);

      if(!isPublicKey(decodedClaimantKey)) {
        throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
      }

      claimantCryptoKey = decodedClaimantKey as PublicKey;

      // convert solution back to string
      solutionString = solution ? solution : undefined;
    } catch (error) {
      throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
    }

    return {
      nonce: nonceString,
      timestamp: timestampNumber,
      verifier: verifierCryptoKey,
      claimant: claimantCryptoKey,
      solution: solutionString
    };
  }
};
