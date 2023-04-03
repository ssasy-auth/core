export enum KeyType {
  Key = "key",
  SecretKey = "secret-key",
  PassKey = "pass-key",
  PublicKey = "public-key",
  PrivateKey = "private-key",
  SharedKey = "shared-key",
}

/**
 * @interface JsonWebKey
 * @description JSON representation of a cryptographic key that follows the [RFC 7517 standard](https://datatracker.ietf.org/doc/html/rfc7517)
 */
export interface JsonWebKey {
  /**
   * Key type:
   * - 'EC' for elliptic curve,
   * - 'RSA' for RSA, and
   * - 'oct' for symmetric keys
   */
  kty?: string | undefined;

  /**
   * Operations that the key can be used for:
   * - 'sign' for signature,
   * - 'verify' for verification,
   * - 'encrypt' for encryption,
   * - 'decrypt' for decryption,
   * - 'wrapKey' for key wrapping,
   * - 'unwrapKey' for key unwrapping,
   * - 'deriveKey' for key derivation,
   * - 'deriveBits' for bit string derivation
   */
  key_ops?: string[];

  /**
   * Algorithm used to generate the key
   */
  alg?: string;

  /**
   * Boolean indicating whether the key is extractable
   */
  ext?: boolean;

  /**
   * Key identifier used to distinguish between keys
   * This property is OPTIONAL.
   */
  kid?: string;

  /**
   * Operations supported by public ke:
   * - 'sig' for signature,
   * - 'enc' for encryption and decryption
   *
   * OPTIONAL and only used for public keys.
   */
  use?: string;

  /* ======== [Symmetric Keys](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4) ======== */

  /**
   * Symmetric key value.
   * OPTIONAL except when the "kty" value is "oct".
   * */
  k?: string;

  /* ======== [Asymmetric Elliptic Curve Params (EC)](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2) ======== */

  /**
   * Cryptographic curve used to generate the elliptic curve key.
   * OPTIONAL except when the "kty" value is "EC".
   */
  crv?: string;

  /**
   * X coordinate of the elliptic curve point.
   * OPTIONAL except when the "kty" value is "EC".
   */
  x?: string;

  /**
   * Y coordinate of the elliptic curve point.
   * OPTIONAL except when the "kty" value is "EC".
   * */
  y?: string;

  /**
   * D parameter of the elliptic curve private key.
   * OPTIONAL except when the "kty" value is "EC" and key is private.
   * */
  d?: string;
}

export interface BaseKey {
    /**
   * Key type
   */
  readonly type: KeyType;

  /**
   * Key domain
   * */
  domain?: string;
}

/**
 * @interface ProcessedKey
 * @description Cryptographic key with WebCryptoLib.CryptoKey in crypto property
 */
export interface ProcessedKey extends BaseKey {
  /**
   * Web crypto key object
   */
  crypto: CryptoKey;
}

/**
 * @interface RawKey
 * @description Cryptographic key with JsonWebKey in crypto property instead of WebCryptoLib.CryptoKey
 */
export interface RawKey extends BaseKey {
  crypto: JsonWebKey;

  /**
   * Hash of the password used to derive the key
   * (only for PassKey)
   */
  readonly hash?: string;

  /** 
   * Salt buffer used to derive the key from a password (note: base64 encoded)
   * (only for PassKey)
   */
  readonly salt?: string;

  /**
   * Number of iterations used to derive the key from a password
   * (only for PassKey)
   */
  readonly iterations?: number;
}

/**
 * @interface GenericKey
 * @description A generic cryptographic key interface that can be used to represent any type of key whether their crypto property is a `CryptoKey` or a `JsonWebKey`
 */
export type GenericKey = ProcessedKey | RawKey;

/**
 * @interface SecretKey
 * @description AES secret key
 */
export interface SecretKey extends ProcessedKey {
  type: KeyType.SecretKey;
}

/**
 * @interface PassKey
 * @description AES key derived from a password
 */
export interface PassKey extends Omit<SecretKey, "type"> {
  type: KeyType.PassKey;

  /**
   * Hash of the password used to derive the key
   * */
  hash: string;

  /**
   * Salt buffer used to derive the key from a password (note: base64 encoded)
   * 
   */
  salt: string;

  /**
   * Number of iterations used to derive the key from a password
   * */
  iterations: number;
}

/**
 * @interface PrivateKey
 * @description Elliptic curve private key
 */
export interface PrivateKey extends ProcessedKey {
  type: KeyType.PrivateKey;
}

/**
 * @interface PublicKey
 * @description Elliptic curve public key
 */
export interface PublicKey extends ProcessedKey {
  type: KeyType.PublicKey;
}

/**
 * @interface SharedKey
 * @description AES secret key shared between two parties using Elliptic Curve Diffie-Hellman
 */
export interface SharedKey extends ProcessedKey {
  type: KeyType.SharedKey;
}

/**
 * @interface KeyPair
 * @description Key pair containing a public and private key
 */
export interface KeyPair {
  public: PublicKey;
  private: PrivateKey;
}
