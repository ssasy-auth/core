export interface Ciphertext {
  /**
   * Encrypted data
   */
  data: string;
  /**
   * Salt (initialization vector) used to encrypt the data
   */
  salt: Uint8Array;
}

export type isCipherText = (ciphertext: unknown) => ciphertext is Ciphertext;