import type { PublicKey } from "./key-interface";

/**
 * Basic ciphertext
 */
export interface StandardCiphertext {
  /**
   * Encrypted data
   */
  readonly data: string;
  
  /**
   * Initialization vector buffer used to encrypt the data. (note: base64 encoded)
   */
  readonly iv: string;

  /**
   * Salt buffer used to build passkey. (note: base64 encoded)
   */
  readonly salt?: string;
}

/**
 * Ciphertext with additional information.
 * 
 * The additional information is optional because it is not 
 */
export interface AdvancedCiphertext extends StandardCiphertext {
  /**
   * The public key of the sender
   */
  sender?: PublicKey;

  /**
   * The public key of the recipient
   */
  recipient?: PublicKey;

  /**
   * The signature of the ciphertext
   */
  readonly signature?: StandardCiphertext;
}

/**
 * @interface Ciphertext
 * @description Represents the encrypted data
 * */
export type Ciphertext = AdvancedCiphertext | StandardCiphertext;