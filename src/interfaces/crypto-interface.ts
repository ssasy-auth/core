import { webcrypto as WebCrypto } from "crypto";
import { Key, SecretKey, PrivateKey, PublicKey } from "./key-interface";

/**
 * @interface CryptoUtil
 * @description Provids cryptographic operations
 * */
export interface CryptoUtil {
  /**
   * Returns a cipher text which is the result of encrypting the plaintext with the key
   * @param key crypto key
   * @param plaintext plain text to encrypt
   * @returns ciphertext
   */
  encrypt: (key: SecretKey | PublicKey, plaintext: string) => Promise<string>;

  /**
   * Returns a plain text which is the result of decrypting the cipher text with the key
   *
   * @param key crypto key
   * @param ciphertext cipher text to decrypt
   * @returns plaintext
   */
  decrypt: (
    key: SecretKey | PrivateKey,
    ciphertext: string
  ) => Promise<string>;

  /**
   * Returns a json web key representation of the key
   *
   * @param key - key to export
   * @returns json web key
   */
  exportKey: (key: Key) => Promise<WebCrypto.JsonWebKey>;

  /**
   * Returns a key from the json web key representation
   *
   * @param jsonWebKey - json web key to import
   * @returns key
   */
  importKey: (jsonWebKey: WebCrypto.JsonWebKey) => Promise<Key>;
}

/**
 * @interface SymmetricUtil
 * @description Provides symmetric cryptographic operations
 * */
export interface SymmetricUtil extends CryptoUtil {
  /**
   * Returns a secret key using the symmetric cryptography algorithm
   *
   * @returns key
   * */
  generateSecret: () => Promise<SecretKey>;
}

/**
 * @interface AsymmetricUtil
 * @description Provides asymmetric cryptographic operations
 * */
export interface AsymmetricUtil extends CryptoUtil {
  /**
   * Returns a new private and public key pair using the elliptic curve cryptography algorithm
   *
   * @returns private key
   * */
  generatePrivateKey: () => Promise<PrivateKey>;

  /**
   * Returns a public key that is derived from the private source key. At a lower level, the public key
   * is actually an AES key that is derived from the private key.
   *
   * @param key private source key
   * @returns public key
   */
  generatePublicKey: (key: PrivateKey) => Promise<PublicKey>;

  /**
   * Returns a signature for the plaintext using the key
   *
   * @param key
   * @param plaintext
   * @returns signature
   */
  sign: (key: PrivateKey, plaintext: string) => Promise<string>;

  /**
   * Returns true if the signature is valid using the key
   *
   * @param key
   * @param signature
   * @returns boolean
   */
  verify: (key: PublicKey, signature: string) => Promise<string>;
}
