import { Challenge } from "../interfaces/challenge-interface";
import { KeyType, PublicKey, RawKey } from "../interfaces/key-interface";
import { KeyModule, KeyChecker } from "./key-mod";
import { ChallengeChecker } from "./challenge-mod";

export const ENCODER_ERROR_MESSAGE = {
  MISSING_KEY: "Key is missing",
  KEY_NOT_SUPPORTED: "Key is not supported",
  INVALID_ENCODING: "Encoding is invalid",
  INVALID_CHALLENGE: "Challenge is invalid",
  INVALID_CHALLENGE_STRING: "Challenge string is invalid"
};

/**
 * Operations for encoding objects for transport.
 */
export const EncoderModule = {
  /**
	 * Operations for encoding cryptographic keys for transport.
	 */
  key: {
    /**
		 * Returns a stringified JSON representation of the public key
		 *
		 * @param key - the public key to convert to a string
		 * @returns string representation of the public key
		 * */
    publicKeyToString: async (key: PublicKey): Promise<string> => {
      if (!KeyChecker.isAsymmetricKey(key) || key.type !== KeyType.PublicKey) {
        throw new Error(ENCODER_ERROR_MESSAGE.KEY_NOT_SUPPORTED);
      }

      const rawKey = await KeyModule.exportKey(key);
      return JSON.stringify(rawKey);
    },
    /**
		 * Returns a public key from a stringyfied JSON representation of the public key
		 *
		 * @param key - the string representation of the public key
		 * @returns the public key
		 * */
    stringToPublicKey: async (key: string): Promise<PublicKey> => {
      if (!key) {
        throw new Error(ENCODER_ERROR_MESSAGE.MISSING_KEY);
      }

      let rawKey: RawKey;

      try {
        rawKey = JSON.parse(key);
      } catch (error) {
        if (error instanceof Error && error.name === "SyntaxError") {
          throw new Error(ENCODER_ERROR_MESSAGE.INVALID_ENCODING);
        }

        throw error;
      }

      return (await KeyModule.importKey(rawKey)) as PublicKey;
    }
  },
  /**
	 * Operations for encoding challenges for transport.
	 */
  challenge: {
    /**
		 * Returns a string representation of the challenge.
		 * String representation is in the format: `<nonce>::<timestamp>::<verifier>::<claimant>::<solution>`
		 *
		 * @param challenge - the challenge to convert to a string
		 * @returns challenge string
		 * */
    challengeToString: async (challenge: Challenge): Promise<string> => {
      if(!ChallengeChecker.isChallenge(challenge)) {
        throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE);
      }
      
      const { nonce, timestamp, verifier, claimant, solution } = challenge;

      // convert nonce to string
      const nonceString = nonce.toString();

      // convert timestamp to string
      const timestampString = timestamp.toString();

      // convert verifier's public key to string
      const verifierString = await EncoderModule.key.publicKeyToString(
        verifier
      );

      // convert claimant's public key to string
      const claimantString = await EncoderModule.key.publicKeyToString(
        claimant
      );

      // convert solution to string
      const solutionString = solution
        ? "::" + solution
        : "";

      return `${nonceString}::${timestampString}::${verifierString}::${claimantString}${solutionString}`;
    },

    /**
		 * Returns a challenge object from a string representation of a challenge
		 *
		 * @param challenge - the string representation of the challenge
		 * @returns challenge object
		 * */
    stringToChallenge: async (challenge: string): Promise<Challenge> => {
      const [ nonce, timestamp, verifier, claimant, solution ] = challenge.split("::");

      let nonceUint8Array: Uint8Array;
      let timestampNumber: number;
      let verifierCryptoKey: PublicKey;
      let claimantCryptoKey: PublicKey;
      let solutionString: string | undefined;

      try {
        // convert nonce.toString() back to Uint8Array
        nonceUint8Array = new Uint8Array(nonce.split(",").map(Number));
  
        // convert timestamp back to number
        timestampNumber = Number(timestamp);
  
        // convert verifier's public key back to CryptoKey
        verifierCryptoKey = await EncoderModule.key.stringToPublicKey(
          verifier
        );
  
        // convert claimant's public key back to CryptoKey
        claimantCryptoKey = await EncoderModule.key.stringToPublicKey(
          claimant
        );
  
        // convert solution back to string
        solutionString = solution
          ? solution
          : undefined;
        
      } catch (error) {
        throw new Error(ENCODER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
      }

      return {
        nonce: nonceUint8Array,
        timestamp: timestampNumber,
        verifier: verifierCryptoKey,
        claimant: claimantCryptoKey,
        solution: solutionString
      };
    }
  }
};
