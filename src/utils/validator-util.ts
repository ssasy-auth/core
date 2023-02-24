import { webcrypto as WebCrypto } from "crypto";
import { CRYPTO_ALGORITHMS } from "../config/algorithm";
import { Key, KeyType } from "../interfaces/key-interface";

/**
   * Returns true if key is a valid Key
   *
   * @param key - key to check
   * @returns boolean
   */
function isKey(key: Key): boolean {
  if (!key) {
    return false;
  }

  if (key.crypto)
    if (!key.type || !Object.values(KeyType).includes(key.type)) {
      // return false if key type is not present or is not a valid key type
      return false;
    }

  // return false if key crypto is not present or is not a valid crypto key
  if (
    !key.crypto || // key.crypto is not present
    (key.crypto instanceof WebCrypto.CryptoKey === false &&
      !isRawKey(key)) // key.crypto is not a valid crypto key or raw key
  ) {
    return false;
  }

  return true;
}

/**
 * Returns true if the key is a valid raw key
 *
 * @param key key
 * @returns boolean
 */
function isRawKey(key: Key): boolean {
  if (!key) {
    return false;
  }

  // return false if key does not have crypto property
  if (!key.crypto) {
    return false;
  }

  const crypto = key.crypto as JsonWebKey;

  if (
    !crypto.kty || // rawKey.crypto.kty is not present
    !crypto.key_ops || // rawKey.crypto.key_ops is not present
    // rawKey.crypto.kty is oct and k property is not present
    (crypto.kty === CRYPTO_ALGORITHMS.AES.jwk.kty &&
      !crypto.k &&
      // rawKey.crypto.kty is EC and x, y property are not present (d is optional)
      crypto.kty === CRYPTO_ALGORITHMS.ECDH.jwk.kty &&
      (!crypto.x || !crypto.y))
  ) {
    return false;
  }

  return true;
}

/**
 * Returns true if key is a valid symmetric key (AES)
 *
 * @param key - key to check
 * @returns boolean
 */
function isSymmetricKey(key: Key): boolean {
  if (!isKey(key)) {
    return false;
  }

  if (
    key.type !== KeyType.SecretKey &&
    key.type !== KeyType.PassKey &&
    key.type !== KeyType.SharedKey
  ) {
    return false;
  }

  if (key.crypto.algorithm.name !== CRYPTO_ALGORITHMS.AES.name) {
    return false;
  }

  return true;
}

/**
 * Returns true if key is a valid asymmetric key (ECDH)
 *
 * @param key - key to check
 * @returns boolean
 */
function isAsymmetricKey(key: Key): boolean {
  if (!isKey(key)) {
    return false;
  }

  if (key.type !== KeyType.PrivateKey && key.type !== KeyType.PublicKey) {
    return false;
  }

  if (key.crypto.algorithm.name !== CRYPTO_ALGORITHMS.ECDH.name) {
    return false;
  }

  return true;
}

/**
 * Functions for validating cryptographic keys
 * */
export const KeyValidator = {
  isKey,
  isRawKey,
  isSymmetricKey,
  isAsymmetricKey
};
