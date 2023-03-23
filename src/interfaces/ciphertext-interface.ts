import type { PublicKey } from "./key-interface";

export interface Ciphertext {
  /**
   * Encrypted data
   */
  data: string;
  
  /**
   * Initialization vector buffer used to encrypt the data. (note: base64 encoded)
   */
  iv: string;

  /**
   * Salt buffer used to build passkey. (note: base64 encoded)
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
