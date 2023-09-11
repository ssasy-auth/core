type SymmetricKeyName = "AES-GCM" | "PBKDF2";
type AsymmetricKeyName = "ECDH" | "ECDSA";
type KeyName = SymmetricKeyName | AsymmetricKeyName;
type CurveName = "P-256" | "P-384" | "P-521"; //  curve >= prime256v1, as recommended by [NIST](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)
type HashName = "SHA-256" | "SHA-384" | "SHA-512";

/**
 * [JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518.html)
 * */
interface JsonAlgorithm {
  /**
   * Key type
   */
  kty: string;
  /**
   * Algorithm
   */
  algo: string;
}

interface BaseAlgorithm {
  /**
   * Algorithm name
   */
  name: KeyName;
  /**
   * JSON Web Algorithm
   */
  jwk: JsonAlgorithm;
}

interface AesAlgorithm extends BaseAlgorithm {
  name: "AES-GCM";
  /**
   * Key length in bits
   */
  length: number;
  /**
   * tag length in bits
   */
  tagLength: number;
}

interface EcdhAlgorithm extends BaseAlgorithm {
  name: "ECDH";

  /**
   * Curve name
   */
  namedCurve: CurveName;
}

interface EcdsAlgorithm extends BaseAlgorithm {
  name: "ECDSA";

  /**
   * Hash algorithm
   */
  hash: HashName;
}

interface PbkdfAlgorithm extends BaseAlgorithm {
  name: "PBKDF2";
  
  /**
   * Hash algorithm
   */
  hash: HashName;
  /**
   * Number of iterations
   */
  iterations: number;
}

interface KeyGenParams {
  /**
   * Algorithm
   */
  algorithm: BaseAlgorithm;
  /**
   * Key can be exported
   */
  exportable: boolean;
  /**
   * Key usage
   */
  usages: KeyUsage[]; // key can be used for encryption and decryption (type assertion)
}

interface SignatureGenParams {
  /**
   * Algorithm
   */
  algorithm: EcdsAlgorithm;
}

interface HashGenParams {
  /**
   * Algorithm
   */
  algorithm: HashName;
}

/**
 * Supported cryptographic algorithms
 */
const CRYPTO_ALGORITHMS = {
  AES: {
    name: "AES-GCM", // aes in galois counter mode
    length: 256,
    tagLength: 128,
    jwk: {
      kty: "oct",
      algo: "A256GCM" 
    } 
  } as AesAlgorithm,
  ECDH: {
    name: "ECDH", // elliptic curve diffie hellman
    namedCurve: "P-256", 
    jwk: {
      kty: "EC",
      algo: "ECDH-ES" 
    } 
  } as EcdhAlgorithm,
  ECDSA: {
    name: "ECDSA", // elliptic curve digital signature algorithm
    hash: "SHA-512" 
  } as EcdsAlgorithm,
  PBKDF2: {
    name: "PBKDF2", // password based key derivation function
    hash: "SHA-512",
    iterations: 100000,
    jwk: {
      kty: "oct",
      algo: "A256GCM" // note: the algorithm used to prepare the key is "PBES2-HS512+A256" but the actual key is A256GCM
    } 
  } as PbkdfAlgorithm,
  HASH: "SHA-512" 
};

/**
 * Default configuration properties for the web crypto api
 */
const CRYPTO_CONFIG = {
  SYMMETRIC: {
    algorithm: CRYPTO_ALGORITHMS.AES,
    exportable: true,
    usages: [ "encrypt", "decrypt" ] 
  } as KeyGenParams,
  ASYMMETRIC: {
    algorithm: CRYPTO_ALGORITHMS.ECDH,
    exportable: true,
    usages: [ "deriveKey" ] 
  } as KeyGenParams,
  SIGNATURE: { algorithm: CRYPTO_ALGORITHMS.ECDSA } as SignatureGenParams,
  HASH: { algorithm: CRYPTO_ALGORITHMS.HASH } as HashGenParams 
};

/**
 * Length of the initialization vector (IV) in bytes
 */
const IV_LENGTH = 16;

/**
 * Length of the salt in bytes (for passkeys)
 */
const SALT_LENGTH = 16;

/**
 * Length of the nonce in bytes (for challenge-response)
 */
const NONCE_LENGTH = 16;

export {
  CRYPTO_ALGORITHMS,
  CRYPTO_CONFIG,
  IV_LENGTH,
  SALT_LENGTH,
  NONCE_LENGTH 
};