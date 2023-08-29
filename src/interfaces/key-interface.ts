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
   * 
   * REQUIRED for all keys
   */
  kty: string | undefined;

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
   * 
   * REQUIRED for all keys
   */
  key_ops: string[];

  /**
   * Algorithm used to generate the key
   * 
   * REQUIRED for all keys
   */
  alg: string;

  /**
   * Boolean indicating whether the key is extractable
   * 
   * REQUIRED for all keys
   */
  ext: boolean;

  /**
   * Key identifier used to distinguish between keys
   * 
   * OPTIONAL
   */
  kid?: string;

  /**
   * Operations supported by public ke:
   * - 'sig' for signature,
   * - 'enc' for encryption and decryption
   *
   * REQUIRED for public keys
   */
  use?: string;

  /* ======== [Symmetric Keys](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.4) ======== */

  /**
   * Symmetric key value.
   * 
   * REQUIRED for symmetric keys.
   * */
  k?: string;

  /* ======== [Asymmetric Elliptic Curve Params (EC)](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2) ======== */

  /**
   * Cryptographic curve used to generate the elliptic curve key.
   * 
   * REQUIRED for private/public keys.
   */
  crv?: string;

  /**
   * X coordinate of the elliptic curve point.
   * 
   * REQUIRED for private/public keys.
   */
  x?: string;

  /**
   * Y coordinate of the elliptic curve point.
   * 
   * REQUIRED for private/public keys.
   * */
  y?: string;

  /**
   * D parameter of the elliptic curve private key.
   * REQUIRED FOR private keys.
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
 * @interface SecureContextKey
 * @description Key in Secure Context (i.e. WebCryptoLib.CryptoKey)
 * 
 * @see https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts
 */
export interface SecureContextKey extends BaseKey {
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
export type GenericKey = SecureContextKey | RawKey;

/**
 * @interface SecretKey
 * @description AES secret key
 */
export interface SecretKey extends SecureContextKey {
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
export interface PrivateKey extends SecureContextKey {
  type: KeyType.PrivateKey;
}

/**
 * @interface PublicKey
 * @description Elliptic curve public key
 */
export interface PublicKey extends SecureContextKey {
  type: KeyType.PublicKey;
}

/**
 * @interface SharedKey
 * @description AES secret key shared between two parties using Elliptic Curve Diffie-Hellman
 */
export interface SharedKey extends SecureContextKey {
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
