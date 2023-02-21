import { webcrypto as WebCrypto } from "crypto";

/**
 * @interface Key
 * @description Cryptographic key
 */
export interface Key {
  /**
   * Key type
   */
  type: "key" | "secret-key" | "public-key" | "private-key";

  /**
   * Key domain
   * */
  domain?: string;

  /**
   * Web crypto key object
   */
  crypto: WebCrypto.CryptoKey;
}

/**
 * @interface SecretKey
 * @description AES secret key
 */
export interface SecretKey extends Key {
  type: "secret-key";
}

/**
 * @interface PrivateKey
 * @description Elliptic curve private key
 */
export interface PrivateKey extends Key {
  type: "private-key";
}

/**
 * @interface PublicKey
 * @description Elliptic curve public key
 */
export interface PublicKey extends Key {
  type: "public-key";
}

/**
 * @interface JsonKey
 * @description JSON representation of a cryptographic key that follows the [RFC 7517 standard](https://datatracker.ietf.org/doc/html/rfc7517)
 */
export interface JsonKey {
  /**
   * Key type ('EC' for elliptic curve and 'RSA' for RSA)
   */
  kty: string;

  /**
   * Operations that the key can be used for ('sign' for signature, 'verify' for verification, 'encrypt' for encryption, 'decrypt' for decryption, 'wrapKey' for key wrapping, 'unwrapKey' for key unwrapping, 'deriveKey' for key derivation, 'deriveBits' for bit string derivation)
   */
  key_ops: string[];

  /**
   * Algorithm used to generate the key
   */
  alg: string;

  /**
   * Operations supported by public key ('sig' for signature, 'enc' for encryption, 'enc' for encryption and decryption).
   * This property is OPTIONAL and is only used for public keys.
   */
  use?: string;
}
