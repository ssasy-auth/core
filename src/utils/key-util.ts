import { KeyType, Key, JsonWebKey } from "../interfaces/key-interface";
import { CRYPTO_ALGORITHMS } from "../config/algorithm"
import { webcrypto as WebCrypto } from "crypto";

/**
 * Returns true if the key is a valid raw key
 * 
 * @param key key
 * @returns boolean
 */
export function isRawKey(key: Key) {
  if (!key || !key.crypto) {
    return false;
  }

  const crypto = key.crypto as JsonWebKey;

  if (
    !crypto.kty ||  // rawKey.crypto.kty is not present
    !crypto.key_ops ||  // rawKey.crypto.key_ops is not present
    (
      // rawKey.crypto.kty is oct and k property is not present
      (crypto.kty === CRYPTO_ALGORITHMS.AES.jwk.kty && !crypto.k) &&
      // rawKey.crypto.kty is EC and x, y property are not present (d is optional)
      (crypto.kty === CRYPTO_ALGORITHMS.ECDH.jwk.kty && (!crypto.x || !crypto.y))
    )
  ) {
    return false;
  }

  return true;
}

/**
 * Returns true if key is a valid Key
 * 
 * @param key - key to check
 * @returns boolean
 */
export function isKey(key: Key) {
  if (!key) {
    return false;
  }

  // return false if key type is not present or is not a valid key type
  if (!key.type || !Object.values(KeyType).includes(key.type)) {
    return false;
  }

  // return false if key crypto is not present or is not a valid crypto key
  if (
    !key.crypto || // key.crypto is not present
    (key.crypto instanceof WebCrypto.CryptoKey === false && !isRawKey(key)) // key.crypto is not a valid crypto key or raw key
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
export function isSymmetricKey(key: Key) {
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
export function isAsymmetricKey(key: Key) {
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