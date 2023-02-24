import { webcrypto as WebCrypto } from "crypto";
import {
  KeyType,
  Key,
  SecretKey,
  PassKey,
  PrivateKey,
  PublicKey,
  SharedKey,
  RawKey,
  JsonWebKey
} from "../interfaces/key-interface";
import { CRYPTO_ERROR } from "../config/messages";
import { CRYPTO_ALGORITHMS, CRYPTO_CONFIG } from "../config/algorithm";
import { KeyValidator } from "./validator-util";

interface GenKeyParams {
	/**
	 * domain to generate the key for
	 */
	domain?: string;
}

interface GenPassKeyParams extends GenKeyParams {
	/**
	 * passphrase to generate the key from
	 */
	passphrase: string;

	/**
	 * salt to use to derive the key from the passphrase
	 */
	salt?: Uint8Array;

	/**
	 * number of iterations to use to derive the key from the passphrase
	 * */
	iterations?: number;
}

interface GenPublicKeyParams extends GenKeyParams {
	/**
	 * private source key
	 */
	privateKey: PrivateKey;
}

interface GenSharedKeyParams extends GenKeyParams {
	/**
	 * a private ECDH key
	 */
	privateKey: PrivateKey;
	/**
	 * a public ECDH key
	 */
	publicKey: PublicKey;
}

/**
 * Functions for generating symmetric and asymmetric cryptographic keys
 */
export const WalletUtil = {
  /**
	 * Returns a symmetric key using the AES-GCM cryptography algorithm.
	 * This operation is for **symmetric** key cryptography.
	 *
	 * @returns secret key
	 * */
  async generateKey(params?: GenKeyParams): Promise<SecretKey> {
    const cryptoKey = await WebCrypto.subtle.generateKey(
      CRYPTO_CONFIG.SYMMETRIC.algorithm,
      CRYPTO_CONFIG.SYMMETRIC.exportable,
      CRYPTO_CONFIG.SYMMETRIC.usages
    );

    return {
      type: KeyType.SecretKey,
      domain: params?.domain,
      crypto: cryptoKey
    };
  },

  /**
	 * Returns a symmetric key using the AES-GCM cryptography algorithm and a passphrase.
	 * This operation is for **symmetric** key cryptography.
	 *
	 * @returns password key
	 * */
  async generatePassKey(params: GenPassKeyParams): Promise<PassKey> {
    const { domain, passphrase, salt, iterations } = params;

    if (typeof passphrase !== "string") {
      throw new Error(CRYPTO_ERROR.SYMMETRIC.INVALID_PASSPHRASE);
    }

    if (salt && !(salt instanceof Uint8Array)) {
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
    const keySalt = salt || WebCrypto.getRandomValues(new Uint8Array(16));

    // prepare iterations for key with provided iterations or use default iterations
    const keyIterations = iterations || CRYPTO_ALGORITHMS.PBKDF2.iterations;

    // generate key from key material
    const cryptoKey = await WebCrypto.subtle.deriveKey(
      {
        ...CRYPTO_ALGORITHMS.PBKDF2,
        salt: keySalt,
        iterations: keyIterations
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
      salt: keySalt,
      iterations: keyIterations,
      hash: CRYPTO_ALGORITHMS.PBKDF2.hash
    };
  },

  /**
	 * Returns a new private and public key pair using the ECDH cryptography algorithm.
	 * This operation is for **asymmetric** key cryptography.
	 *
	 * @returns private key
	 * */
  async generatePrivateKey(params?: GenKeyParams): Promise<PrivateKey> {
    const { privateKey } = await WebCrypto.subtle.generateKey(
      CRYPTO_CONFIG.ASYMMETRIC.algorithm,
      CRYPTO_CONFIG.ASYMMETRIC.exportable,
      CRYPTO_CONFIG.ASYMMETRIC.usages
    );

    return {
      type: KeyType.PrivateKey,
      domain: params?.domain,
      crypto: privateKey
    };
  },

  /**
	 * Returns a public key that is derived from the private source key. At a lower level, the public key
	 * is actually an AES key that is derived from the private key.
	 * This operation is for **asymmetric** key cryptography.
	 *
	 * @returns public key
	 */
  async generatePublicKey(params: GenPublicKeyParams): Promise<PublicKey> {
    const { domain, privateKey } = params;

    if (!KeyValidator.isAsymmetricKey(privateKey)) {
      throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_KEY);
    }

    if (privateKey.type !== KeyType.PrivateKey) {
      throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
    }

    // convert private key to public key
    const privateJsonWebKey = await WebCrypto.subtle.exportKey(
      "jwk",
      privateKey.crypto
    );
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
    };
  },

  /**
	 * Returns a shared key that is derived from the private key of one party
	 * and the public key of another party.
	 * This operation is for **asymmetric** key cryptography.
	 *
	 * @returns shared key
	 */
  async generateSharedKey(params: GenSharedKeyParams): Promise<SharedKey> {
    const { domain, privateKey, publicKey } = params;

    if (!KeyValidator.isAsymmetricKey(privateKey)) {
      throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
    }

    if (!KeyValidator.isAsymmetricKey(publicKey)) {
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
    };
  },

  /**
   * Returns a json web key representation of the key.
   * This operation is for **symmetric** and **asymmetric** key cryptography.
   *
   * @param key - key to export
   * @returns json web key
   */
  async exportKey(key: Key): Promise<RawKey> {
    if (!KeyValidator.isKey(key)) {
      throw new Error(CRYPTO_ERROR.COMMON.INVALID_KEY);
    }

    const jsonKey: JsonWebKey = await WebCrypto.subtle.exportKey("jwk", key.crypto);

    if (key.type === KeyType.PassKey) {
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

  /**
   * Returns a key from the json web key representation.
   * This operation is for **symmetric** and **asymmetric** key cryptography.
   *
   * @param rawKey - json web key to import
   * @returns key
   */
  async importKey(rawKey: RawKey): Promise<SecretKey | PassKey | PrivateKey | PublicKey> {

    if (!KeyValidator.isRawKey(rawKey as Key)) {
      throw new Error(CRYPTO_ERROR.RAW.INVALID_KEY);
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

    } else {
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
};