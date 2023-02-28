import { PublicKey } from "./key-interface";

export interface Ciphertext {
  /**
   * Encrypted data
   */
  data: string;
  
  /**
   * Salt (initialization vector) used to encrypt the data
   */
  salt: Uint8Array;

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