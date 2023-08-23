import { KeyType } from "../interfaces";
import { KeyModule, KeyChecker } from "./key-mod";
import { ChallengeChecker } from "./challenge-mod";
import { CryptoChecker } from "./crypto-mod";
import type {
  PublicKey,
  RawKey,
  GenericKey,
  Challenge,
  Ciphertext,
  StandardCiphertext,
  AdvancedCiphertext
} from "../interfaces";

export const ENCODER_ERROR_MESSAGE = {
  INVALID_KEY: "Key is invalid or not supported",
  INVALID_KEY_STRING: "Key is missing or invalid",
  INVALID_CHALLENGE: "Challenge is missing or invalid",
  INVALID_CHALLENGE_STRING: "Challenge string is invalid",
  INVALID_CIPHERTEXT: "Ciphertext is invalid",
  INVALID_CIPHERTEXT_STRING: "Ciphertext string is invalid or missing"
};

/**
 * A ciphertext that has been encoded for transport. This means that the
 * sender and recipient public keys have been encoded to strings as well as
 * the signature.
 */
interface ShallowCiphertext extends Omit<Ciphertext, "sender" | "recipient" | "signature"> {
  sender?: string;
  recipient?: string;
  signature?: string;
}

/**
 * Returns true if key is a valid asymmetric **public** key.
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
	 * Returns a string representation of a key.
   * 
   * The representation has the following format:
   * `JSON.stringify(RawKey)`
	 *
	 * @param key - key
	 * @returns key
	 * */
  encodeKey: async (key: GenericKey): Promise<string> => {
    let rawKey: RawKey;

    if (!KeyChecker.isKey(key)) {
      throw new Error(ENCODER_ERROR_MESSAGE.INVALID_KEY);
    }

    if(KeyChecker.isRawKey(key)) {
      rawKey = key as RawKey;
    } else {
      rawKey = await KeyModule.exportKey(key);
    }

    const keyString = JSON.stringify(rawKey);

    return keyString
  },
  /**
	 * Returns a key object from a string representation (JSON stringified) of the key
	 *
	 * @param key - the string representation of the key
	 * @returns key
	 * */
  decodeKey: async (keyString: string): Promise<GenericKey> => {
    if (!keyString) {
      throw new Error(ENCODER_ERROR_MESSAGE.INVALID_KEY_STRING);
    }

    let rawKey: RawKey;

    try {
      rawKey = JSON.parse(keyString);
    } catch (error) {
      if (error instanceof Error && error.name === "SyntaxError") {
        throw new Error(ENCODER_ERROR_MESSAGE.INVALID_KEY_STRING);
      }

      throw `Error parsing key: ${error}`
    }

    return await KeyModule.importKey(rawKey);
  },
  /**
	 * Returns a string representation of a challenge. 
   * 
   * The representation has the following format:
   * `<nonce>::<timestamp>::<verifier>::<claimant>::<solution>`
	 *
	 * @param challenge - the challenge to convert to a string
	 * @returns challenge in string format
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
    const solutionString = solution;

    // only include solution if it exists
    return solution 
      ? `${nonceString}::${timestampString}::${verifierString}::${claimantString}::${solutionString}`
      : `${nonceString}::${timestampString}::${verifierString}::${claimantString}`;
  },

  /**
	 * Returns a challenge object from a string representation of a challenge.
	 *
	 * @param challenge - the string representation of the challenge
	 * @returns challenge object
	 * */
  decodeChallenge: async (challengeString: string): Promise<Challenge> => {
    const [ nonceString, timestampString, verifierPublicKeyString, claimantPublicKeyString, solutionString ] = challengeString.split("::");

    let nonce: string;
    let timestamp: number;
    let verifier: PublicKey;
    let claimant: PublicKey;
    let solution: string | undefined;

    try {
      // convert nonce.toString() back to Uint8Array
      nonce = nonceString;

      // convert timestamp back to number
      timestamp = Number(timestampString);

      // convert verifier's public key back to CryptoKey
      const verifierKey = await EncoderModule.decodeKey(verifierPublicKeyString);

      if(!isPublicKey(verifierKey)) {
        throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
      }
      
      // convert claimant's public key back to CryptoKey
      const claimantKey = await EncoderModule.decodeKey(claimantPublicKeyString);

      if(!isPublicKey(claimantKey)) {
        throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
      }

      // set verifier
      verifier = verifierKey as PublicKey;
      
      // set claimant
      claimant = claimantKey as PublicKey;

      // convert solution back to string
      solution = solutionString ? solutionString : undefined;

    } catch (error) {
      throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
    }

    return {
      nonce,
      timestamp,
      verifier,
      claimant,
      solution
    };
  },
  /**
   * Returns a string representation of the ciphertext.
   * 
   * The representation has the following format: 
   * `<iv>::<ciphertext>::<tag>::<sender>::<recipient>::<signature>`
   * 
   * @param ciphertext - the ciphertext to convert to a string
   */
  encodeCiphertext: async (ciphertext: Ciphertext): Promise<string> => {
    if(!CryptoChecker.isCiphertext(ciphertext)) {
      throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    const shallowCiphertext: ShallowCiphertext = {
      ...(ciphertext as StandardCiphertext) 
    };

    if(
      (ciphertext as AdvancedCiphertext).sender ||
      (ciphertext as AdvancedCiphertext).recipient ||
      (ciphertext as AdvancedCiphertext).signature
    ) {
      const advancedCiphertext = ciphertext as AdvancedCiphertext;

      if(advancedCiphertext.sender) {
        shallowCiphertext.sender = await EncoderModule.encodeKey(advancedCiphertext.sender);
      }

      if(advancedCiphertext.recipient) {
        shallowCiphertext.recipient = await EncoderModule.encodeKey(advancedCiphertext.recipient);
      }

      if(advancedCiphertext.signature) {
        shallowCiphertext.signature = await EncoderModule.encodeCiphertext(advancedCiphertext.signature);
      }
    }

    return JSON.stringify(shallowCiphertext);
  },
  /**
   * Returns a ciphertext object from a string representation of a ciphertext.
   * 
   * @param ciphertextString - the string representation of the ciphertext
   */
  decodeCiphertext: async (ciphertextString: string): Promise<Ciphertext> => {
    let shallowCiphertext: ShallowCiphertext;

    try {
      shallowCiphertext = JSON.parse(ciphertextString);
    } catch (error) {
      if (error instanceof Error && error.name === "SyntaxError") {
        throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING);
      }

      throw `Error parsing ciphertext: ${error}`
    }

    const ciphertext = {
      ...shallowCiphertext
    } as Ciphertext;

    if(
      shallowCiphertext.sender ||
      shallowCiphertext.recipient ||
      shallowCiphertext.signature
    ) {

      try {
        return {
          ...shallowCiphertext,
          sender: shallowCiphertext.sender ? await EncoderModule.decodeKey(shallowCiphertext.sender) : undefined,
          recipient: shallowCiphertext.recipient ? await EncoderModule.decodeKey(shallowCiphertext.recipient) : undefined,
          signature: shallowCiphertext.signature ? await EncoderModule.decodeCiphertext(shallowCiphertext.signature) : undefined
        } as AdvancedCiphertext;
      } catch (error) {
        throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING);
      }
    }

    return ciphertext as StandardCiphertext;
  }
};
