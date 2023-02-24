import { webcrypto as WebCrypto } from "crypto"
import { CRYPTO_ERROR } from "../config/messages";
import { CRYPTO_ALGORITHMS } from "../config/algorithm";
import { KeyType, JsonWebKey, Key, RawKey, SecretKey, PassKey, PrivateKey, PublicKey } from "../interfaces/key-interface"
import { CryptoUtil as ICryptoUtil, Ciphertext, GenPassKeyParams } from "../interfaces/crypto-interface"
import { isKey, isRawKey, isAsymmetricKey } from "./key-util"

/**
 * Default configuration properties for the crypto util module
 */
export const CRYPTO_CONFIG = {
  SYMMETRIC: {
    algorithm: CRYPTO_ALGORITHMS.AES,
    exportable: true, // key can be exported
    usages: [ "encrypt", "decrypt" ] as WebCrypto.KeyUsage[] // key can be used for encryption and decryption (type assertion)
  },
  ASYMMETRIC: {
    algorithm: CRYPTO_ALGORITHMS.ECDH,
    exportable: true, // key can be exported
    usages: [ "deriveKey" ] as WebCrypto.KeyUsage[] // key can be used for generating other keys (type assertion)
  }
}

export const CryptoUtil: ICryptoUtil = {
  async generateKey({ domain } = {}) {
    const cryptoKey = await WebCrypto.subtle.generateKey(
      CRYPTO_CONFIG.SYMMETRIC.algorithm,
      CRYPTO_CONFIG.SYMMETRIC.exportable,
      CRYPTO_CONFIG.SYMMETRIC.usages
    )

    return {
      type: KeyType.SecretKey,
      domain: domain,
      crypto: cryptoKey
    }
  },

  async generatePassKey(
    { 
      passphrase, 
      salt, 
      iterations, 
      domain 
    }: GenPassKeyParams
  ) {
    if(typeof passphrase !== "string") {
      throw new Error(CRYPTO_ERROR.SYMMETRIC.INVALID_PASSPHRASE);
    }

    if(salt && !(salt instanceof Uint8Array)) {
      throw new Error(CRYPTO_ERROR.SYMMETRIC.INVALID_SALT);
    }

    // encode passphrase
    const encoder = new TextEncoder();
    const encodedPassphrase = encoder.encode(passphrase);
    
    // prepare key material for PBKDF2
    const keyMaterial = await WebCrypto.subtle.importKey(
      "raw",
      encodedPassphrase,
      CRYPTO_ALGORITHMS.PBKDF2.name,
      false,
      [ "deriveBits", "deriveKey" ]
    );

    // prepare salt for key with provided salt or generate random salt
    salt = salt || WebCrypto.getRandomValues(new Uint8Array(16));

    // prepare iterations for key with provided iterations or use default iterations
    iterations = iterations || CRYPTO_ALGORITHMS.PBKDF2.iterations;

    // generate key from key material
    const cryptoKey = await WebCrypto.subtle.deriveKey(
      {
        ...CRYPTO_ALGORITHMS.PBKDF2,
        iterations: iterations,
        salt: salt
      },
      keyMaterial,
      CRYPTO_CONFIG.SYMMETRIC.algorithm,
      CRYPTO_CONFIG.SYMMETRIC.exportable,
      CRYPTO_CONFIG.SYMMETRIC.usages
    );

    return {
      type: KeyType.PassKey,
      domain: domain,
      crypto: cryptoKey,
      salt: salt,
      iterations: iterations,
      hash: CRYPTO_ALGORITHMS.PBKDF2.hash
    }
  },

  async generatePrivateKey({ domain } = {}) {
    const { privateKey } = await WebCrypto.subtle.generateKey(
      CRYPTO_CONFIG.ASYMMETRIC.algorithm,
      CRYPTO_CONFIG.ASYMMETRIC.exportable,
      CRYPTO_CONFIG.ASYMMETRIC.usages
    )

    return {
      type: KeyType.PrivateKey,
      domain: domain,
      crypto: privateKey
    }
  },

  async generatePublicKey({ privateKey, domain }) {
    if(!isKey(privateKey)) {
      throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_KEY);
    }

    if (privateKey.type !== KeyType.PrivateKey) {
      throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
    }

    // convert private key to public key
    const privateJsonWebKey = await WebCrypto.subtle.exportKey("jwk", privateKey.crypto);
    // delete private key properties
    delete privateJsonWebKey.d;

    // import public key from JsonWebKey (without private key properties)
    const publicKey = await WebCrypto.subtle.importKey(
      "jwk",
      privateJsonWebKey,
      CRYPTO_CONFIG.ASYMMETRIC.algorithm,
      CRYPTO_CONFIG.ASYMMETRIC.exportable,
      CRYPTO_CONFIG.ASYMMETRIC.usages
    );

    return {
      type: KeyType.PublicKey,
      domain: domain,
      crypto: publicKey
    }
  },

  async generateSharedKey({ privateKey, publicKey, domain }) {
    if (!isAsymmetricKey(privateKey)) {
      throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
    }

    if (!isAsymmetricKey(publicKey)) {
      throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_PUBLIC_KEY);
    }

    if ((privateKey as Key).type === (publicKey as Key).type) {
      throw new Error(CRYPTO_ERROR.ASYMMETRIC.IDENTICAL_KEY_TYPES);
    }

    const sharedKey = await WebCrypto.subtle.deriveKey(
      {
        name: CRYPTO_CONFIG.ASYMMETRIC.algorithm.name,
        public: publicKey.crypto
      },
      privateKey.crypto,
      CRYPTO_CONFIG.SYMMETRIC.algorithm,
      CRYPTO_CONFIG.SYMMETRIC.exportable,
      CRYPTO_CONFIG.SYMMETRIC.usages
    );

    return {
      type: KeyType.SharedKey,
      domain: domain,
      crypto: sharedKey
    }
  },

  async exportKey(key: Key) {
    if(!isKey(key)) {
      throw new Error(CRYPTO_ERROR.COMMON.INVALID_KEY);
    }
    
    const jsonKey: JsonWebKey = await WebCrypto.subtle.exportKey("jwk", key.crypto);

    if(key.type === KeyType.PassKey) {
      return {
        type: key.type,
        domain: key.domain,
        crypto: jsonKey,
        hash: (key as PassKey).hash,
        salt: (key as PassKey).salt,
        iterations: (key as PassKey).iterations
      };
    }

    return {
      type: key.type,
      domain: key.domain,
      crypto: jsonKey
    }
  },

  async importKey(rawKey: RawKey) {

    if (!isRawKey(rawKey as Key)) {
      throw new Error(CRYPTO_ERROR.RAW.INVALID_RAW_KEY);
    }

    if (rawKey.type === KeyType.PrivateKey || rawKey.type === KeyType.PublicKey) {
      const asymmetricKey = await WebCrypto.subtle.importKey(
        "jwk",
        rawKey.crypto,
        CRYPTO_CONFIG.ASYMMETRIC.algorithm,
        CRYPTO_CONFIG.ASYMMETRIC.exportable,
        CRYPTO_CONFIG.ASYMMETRIC.usages
      )

      const key = {
        type: rawKey.type,
        domain: rawKey.domain,
        crypto: asymmetricKey
      };

      return rawKey.type === KeyType.PrivateKey 
        ? key as PrivateKey
        : key as PublicKey

    }else {
      const cryptoKey = await WebCrypto.subtle.importKey(
        "jwk",
        rawKey.crypto,
        CRYPTO_CONFIG.SYMMETRIC.algorithm,
        CRYPTO_CONFIG.SYMMETRIC.exportable,
        CRYPTO_CONFIG.SYMMETRIC.usages
      );

      if (rawKey.type === KeyType.PassKey) {
        return {
          type: rawKey.type,
          domain: rawKey.domain,
          crypto: cryptoKey,
          hash: (rawKey as PassKey).hash,
          salt: (rawKey as PassKey).salt,
          iterations: (rawKey as PassKey).iterations
        } as PassKey;
      }

      return {
        type: rawKey.type,
        domain: rawKey.domain,
        crypto: cryptoKey
      } as SecretKey;
    }
  }
}