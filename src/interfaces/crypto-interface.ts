import { Key, SharedKey, PrivateKey, PublicKey, RawKey, PassKey, SecretKey } from "./key-interface";

export interface GenKeyParams {
  /**
   * domain to generate the key for
   */
  domain?: string;
}

export interface GenPassKeyParams extends GenKeyParams {
  /**
   * passphrase to generate the key from
   */
  passphrase: string;

  /**
   * salt to use to derive the key from the passphrase
   */
  salt?: Uint8Array;

  /**
   * number of iterations to use to derive the key from the passphrase
   * */
  iterations?: number;
}

export interface GenPublicKeyParams extends GenKeyParams {
  /**
   * private source key
   */
  privateKey: PrivateKey;
}

export interface GenSharedKeyParams extends GenKeyParams {
  /**
   * a private ECDH key
   */
  privateKey: PrivateKey;
  /**
   * a public ECDH key
   */
  publicKey: PublicKey;
}

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

/**
 * @interface CryptoUtil
 * @description Provides operations for symmetric and asymmetric cryptography
 * */
export interface CryptoUtil {
  /**
   * Returns a symmetric key using the AES-GCM cryptography algorithm.
   * This operation is for **symmetric** key cryptography.
   *
   * @returns secret key
   * */
  generateKey: (params?: GenKeyParams) => Promise<SecretKey>;

  /**
   * Returns a symmetric key using the AES-GCM cryptography algorithm and a passphrase.
   * This operation is for **symmetric** key cryptography.
   *
   * @returns password key
   * */
  generatePassKey: (params: GenPassKeyParams) => Promise<PassKey>;

  /**
   * Returns a new private and public key pair using the ECDH cryptography algorithm.
   * This operation is for **asymmetric** key cryptography.
   *
   * @returns private key
   * */
  generatePrivateKey: (params?: GenKeyParams) => Promise<PrivateKey>;

  /**
   * Returns a public key that is derived from the private source key. At a lower level, the public key
   * is actually an AES key that is derived from the private key.
   * This operation is for **asymmetric** key cryptography.
   *
   * @returns public key
   */
  generatePublicKey: (params: GenPublicKeyParams) => Promise<PublicKey>;

  /**
   * Returns a shared key that is derived from the private key of one party
   * and the public key of another party.
   * This operation is for **asymmetric** key cryptography.
   * 
   * @returns shared key
   */
  generateSharedKey: (params: GenSharedKeyParams) => Promise<SharedKey>;

  /**
   * Returns a signature for the plaintext using the key.
   * This operation is for **asymmetric** key cryptography.
   *
   * @param key - private key
   * @param plaintext - plain text to sign
   * @returns signature
   */
  sign: (key: PrivateKey, plaintext: string) => Promise<string>;

  /**
   * Returns true if the signature is valid using the key.
   * This operation is for **asymmetric** key cryptography.
   *
   * @param key - public key
   * @param signature - signature to verify
   * @returns boolean
   */
  verify: (key: PublicKey, signature: string) => Promise<string>;

  /**
   * Returns a cipher text which is the result of encrypting the plaintext with the key.
   * This operation is for **symmetric** key cryptography.
   * 
   * @param key - crypto key
   * @param plaintext - plain text to encrypt
   * @returns ciphertext
   */
  encrypt: (key: SecretKey | PassKey | SharedKey, plaintext: string) => Promise<Ciphertext>;

  /**
   * Returns a plain text which is the result of decrypting the cipher text with the key.
   * This operation is for **symmetric** key cryptography.
   *
   * @param key - crypto key
   * @param ciphertext - cipher text to decrypt
   * @returns plaintext
   */
  decrypt: (
    key: SecretKey | PassKey | SharedKey,
    ciphertext: Ciphertext
  ) => Promise<string>;

  /**
   * Returns a json web key representation of the key.
   * This operation is for **symmetric** and **asymmetric** key cryptography.
   *
   * @param key - key to export
   * @returns json web key
   */
  exportKey: (key: Key) => Promise<RawKey>;

  /**
   * Returns a key from the json web key representation.
   * This operation is for **symmetric** and **asymmetric** key cryptography.
   *
   * @param jsonWebKey - json web key to import
   * @returns key
   */
  importKey: (jsonWebKey: RawKey) => Promise<SecretKey | PassKey | PrivateKey | PublicKey>;
}
