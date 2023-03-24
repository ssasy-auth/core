import type { PublicKey } from "./key-interface";

/**
 * @interface Challenge
 * @description Represents the authentication challenge
 */
export interface Challenge {
  /**
   * A random nonce. (note: base64 encoded)
   */
  readonly nonce: string;

  /**
   * A digest of the nonce
   * 
   */
  solution?: string;

  /**
   * The timestamp of the challenge
   */
  readonly timestamp: number;

  /**
   * The public key of the user that created the challenge
   */
  readonly verifier: PublicKey;

  /**
   * The public key of the user that will solve the challenge
   * */
  readonly claimant: PublicKey;
}

/**
 * @interface isChallenge
 * @description Type guard for the Challenge interface
 */
export type isChallenge = (challenge: unknown) => challenge is Challenge;
