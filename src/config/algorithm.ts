/**
 * Supported key types according to [JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518.html)
 * */
export const JSON_WEB_ALGORITHMS = {
  AES: {
    kty: "oct",
    algo: "A256GCM"
  },
  ECDH: {
    kty: "EC",
    algo: "ECDH-ES"
  },
  PBKDF2: {
    kty: "oct",
    algo: "A256GCM" // the algorithm used to prepare the key is "PBES2-HS512+A256" but the actual key is A256GCM
  }
}

/**
 * Supported cryptographic algorithms
 */
export const CRYPTO_ALGORITHMS = {
  AES: {
    name: "AES-GCM", // aes in galois counter mode
    length: 256, // 256 bit key
    tagLength: 128, // 128 bit tag
    jwk: JSON_WEB_ALGORITHMS.AES // json web algorithm for aes
  },
  ECDH: {
    name: "ECDH", // elliptic curve diffie hellman
    namedCurve: "P-256", // prime256v1 curve, at the very least, as recommended by [NIST](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)
    jwk: JSON_WEB_ALGORITHMS.ECDH // json web algorithm for ECDH
  },
  PBKDF2: {
    name: "PBKDF2", // password based key derivation function 2
    hash: "SHA-512", // sha256 hash
    iterations: 100000, // 100000 iterations
    jwk: JSON_WEB_ALGORITHMS.PBKDF2 // json web algorithm for PBKDF2
  }
}