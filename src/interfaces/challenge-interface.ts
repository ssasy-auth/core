import { PublicKey } from "./key-interface";
import { Ciphertext } from "./ciphertext-interface";

/**
 * @interface Challange
 * @description Represents the authentication challenge
 */
export interface Challange {
  /**
   * The public key of the user who sent the challenge
   */
  creator: PublicKey;

  /**
   * The public key of the user who will solve the challenge
   * */
  contributer: PublicKey;

  /**
   * The encrypted challenge
   */
  problem: Ciphertext;
}

/**
 * @interface isChallenge
 * @description Type guard for the Challange interface
 */
export type isChallenge = (challenge: unknown) => challenge is Challange;