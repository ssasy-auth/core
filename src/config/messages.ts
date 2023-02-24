/**
 * @fileoverview Messages used in the application
 */

/**
 * Error messages for the unit tests
 */
export const TEST_ERROR = {
  DID_NOT_THROW: "Did not throw an error"
};

/**
 * Error messages for the crypto operations
 */
export const CRYPTO_ERROR = {
  ASYMMETRIC: {
    INVALID_KEY: "Key is not a valid asymmetric key (ECDH)",
    INVALID_PRIVATE_KEY: "Key is not a private key",
    INVALID_PUBLIC_KEY: "Key is not a public key",
    IDENTICAL_KEY_TYPES: "Keys are of the same type (public or private)"
  },
  SYMMETRIC: {
    INVALID_KEY: "Key is not a valid symmetric key (AES)",
    INVALID_SALT: "Salt is not a valid uint8array",
    INVALID_ENCRYPT_KEY: "Encryption key is not a valid symmetric key",
    INVALID_DECRYPT_KEY: "Decryption key is not a valid symmetric key",
    INVALID_PASSPHRASE: "Passphrase is not a string",
    INVALID_PLAINTEXT: "Plaintext is not a string",
    INVALID_CIPHERTEXT: "Ciphertext is not valid Ciphertext object",
    WRONG_KEY: "Key is not the correct key for this ciphertext",
    WRONG_PASSPHRASE: "Passphrase is not the correct passphrase for this ciphertext"
  },
  RAW: {
    INVALID_KEY: "Key is not a raw key"
  },
  COMMON: {
    INVALID_KEY: "Key is not a valid key",
    KEY_NOT_SUPPORTED: "Key type is not supported"
  }
}