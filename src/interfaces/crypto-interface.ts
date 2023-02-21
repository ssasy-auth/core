import { webcrypto as WebCrypto } from "crypto";
import { Key, SecretKey, PrivateKey, PublicKey } from "./key-interface";

/**
 * @interface CryptoUtil
 * @description Provids cryptographic operations
 * */
export interface CryptoUtil {
  /**
   * Returns a cipher text which is the result of encrypting the plaintext with the key
   * @param key - crypto key
   * @param plaintext - plain text to encrypt
   * @returns ciphertext
   */
  encrypt: (key: SecretKey | PublicKey, plaintext: string) => Promise<string>;

  /**
   * Returns a plain text which is the result of decrypting the cipher text with the key
   *
   * @param key - crypto key
   * @param ciphertext - cipher text to decrypt
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
   * @param domain - domain to generate the key for
   * @returns key
   * */
  generateSecret: (domain?: string) => Promise<SecretKey>;
}

/**
 * @interface AsymmetricUtil
 * @description Provides asymmetric cryptographic operations
 * */
export interface AsymmetricUtil extends CryptoUtil {
  /**
   * Returns a new private and public key pair using the elliptic curve cryptography algorithm
   *
   * @param domain - domain to generate the key for
   * @returns private key
   * */
  generatePrivateKey: (domain?: string) => Promise<PrivateKey>;

  /**
   * Returns a public key that is derived from the private source key. At a lower level, the public key
   * is actually an AES key that is derived from the private key.
   *
   * @param key - private source key
   * @param domain - domain to generate the key for
   * @returns public key
   */
  generatePublicKey: (key: PrivateKey, domain?: string) => Promise<PublicKey>;

  /**
   * Returns a signature for the plaintext using the key
   *
   * @param key - private key
   * @param plaintext - plain text to sign
   * @returns signature
   */
  sign: (key: PrivateKey, plaintext: string) => Promise<string>;

  /**
   * Returns true if the signature is valid using the key
   *
   * @param key - public key
   * @param signature - signature to verify
   * @returns boolean
   */
  verify: (key: PublicKey, signature: string) => Promise<string>;
}
