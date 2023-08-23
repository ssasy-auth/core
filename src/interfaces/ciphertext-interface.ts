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
   * Sender public key
   */
  sender?: PublicKey;

  /**
   * Recipient public key
   */
  recipient?: PublicKey;

  /**
   * Ciphertext signature
   */
  readonly signature?: StandardCiphertext;
}

/**
 * @interface Ciphertext
 * @description Represents the encrypted data
 * */
export type Ciphertext = AdvancedCiphertext | StandardCiphertext;