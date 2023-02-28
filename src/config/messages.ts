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
  },
  HASH: {
    INVALID_STRING: "Input is not a valid string"
  }
}

/**
 * Error messages for the challenge operations
 * */
export const CHALLENGE_ERROR = {
  INVALID_CHALLENGE: "Challenge is not valid",
  INVALID_NONCE: "Nonce is not a valid uint8array",
  INVALID_TIMESTAMP: "Timestamp is not a valid number",
  INVALID_VERIFIER_PUBLIC_KEY: "Verifier's public key is not valid",
  INVALID_VERIFIER_PRIVATE_KEY: "Verifier's private key is not valid",
  INVALID_CLAIMANT_PUBLIC_KEY: "Claimant's public key is not valid",
  INVALID_CLAIMANT_PRIVATE_KEY: "Claimant's private key is not valid",
  EXPIRED_CHALLENGE: "Challenge has expired",
  MISSING_KEY: "Key is missing",
  MISSING_CHALLENGE: "Challenge is missing",
  MISSING_SOLUTION: "Solution is missing",
  CLAIMANT_MISMATCH: "Claimant does not match the challenge claimant",
  VERIFIER_MISMATCH: "Verifier does not match the challenge verifier"
};
