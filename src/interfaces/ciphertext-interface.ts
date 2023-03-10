import type { PublicKey } from "./key-interface";

export interface Ciphertext {
  /**
   * Encrypted data
   */
  data: string;
  
  /**
   * Initialization vector used to encrypt the data.
   * 
   * Note: although the `iv` is stored as a string, it is a 
   * base64 encoded Uint8Array and should be converted to
   * a Uint8Array before use.
   */
  iv: string;

  /**
   * Salt (initialization vector) used to build passkey
   * 
   * Note: although the `salt` is stored as a string, it is a 
   * base64 encoded Uint8Array and should be converted to
   * a Uint8Array before use.
   */
  salt?: string;

  /**
   * The public key of the sender
   */
  sender?: PublicKey;

  /**
   * The public key of the recipient
   */
  recipient?: PublicKey;
}

export type isCipherText = (ciphertext: unknown) => ciphertext is Ciphertext;