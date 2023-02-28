import { webcrypto as WebCrypto } from "crypto";
import { CRYPTO_ERROR } from "../config/messages";
import { CRYPTO_ALGORITHMS, CRYPTO_CONFIG } from "../config/algorithm";
import { Ciphertext } from "../interfaces/ciphertext-interface";
import { KeyType, Key, JsonWebKey, SecretKey, PassKey, PrivateKey, PublicKey, SharedKey, RawKey } from "../interfaces/key-interface";

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
export const CryptoMod = {
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

    if (!KeyHelper.isAsymmetricKey(privateKey)) {
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

    if (!KeyHelper.isAsymmetricKey(privateKey)) {
      throw new Error(CRYPTO_ERROR.ASYMMETRIC.INVALID_PRIVATE_KEY);
    }

    if (!KeyHelper.isAsymmetricKey(publicKey)) {
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
   * Returns a cipher text which is the result of encrypting the plaintext with the key.
   * This operation is for **symmetric** key cryptography.
   * 
   * @param key - crypto key
   * @param plaintext - plain text to encrypt
   * @param sender - sender public key (optional for shared key)
   * @param recipient - recipient public key (optional for shared key)
   * @returns ciphertext
   */
  async encrypt(key: SecretKey | PassKey | SharedKey, plaintext: string, sender?: PublicKey, recipient?: PublicKey): Promise<Ciphertext> {
    if (!KeyHelper.isSymmetricKey(key)) {
      throw new Error(CRYPTO_ERROR.SYMMETRIC.INVALID_KEY);
    }

    if (typeof plaintext !== "string") {
      throw new Error(CRYPTO_ERROR.SYMMETRIC.INVALID_PLAINTEXT);
    }

    // initialization vector
    const salt = WebCrypto.getRandomValues(new Uint8Array(12));

    // encrypt plaintext
    const ciphertextBuffer = await WebCrypto.subtle.encrypt(
      {
        ...CRYPTO_CONFIG.SYMMETRIC.algorithm,
        iv: salt
      },
      key.crypto,
      Buffer.from(plaintext)
    );

    return {
      data: Buffer.from(ciphertextBuffer).toString("base64"),
      salt: salt,
      sender: sender,
      recipient: recipient
    }
  },

  /**
   * Returns a plain text which is the result of decrypting the cipher text with the key.
   * This operation is for **symmetric** key cryptography.
   *
   * @param key - crypto key
   * @param ciphertext - cipher text to decrypt
   * @returns plaintext
   */
  async decrypt(key: SecretKey | PassKey | SharedKey, ciphertext: Ciphertext): Promise<string> {
    // throw error if key is not a shared or pass key
    if (!KeyHelper.isSymmetricKey(key)) {
      throw new Error(CRYPTO_ERROR.SYMMETRIC.INVALID_KEY);
    }

    // throw error if ciphertext is not a valid ciphertext
    if (!ciphertext || !ciphertext.data || !ciphertext.salt) {
      throw new Error(CRYPTO_ERROR.SYMMETRIC.INVALID_CIPHERTEXT);
    }

    let plaintextBuffer: ArrayBuffer;

    try {
      plaintextBuffer = await WebCrypto.subtle.decrypt(
        {
          ...CRYPTO_CONFIG.SYMMETRIC.algorithm,
          iv: ciphertext.salt
        },
        key.crypto,
        Buffer.from(ciphertext.data, "base64")
      );
    } catch (error) {
      if (
        error instanceof Error &&
        (error.name === "InvalidAccessError" || error.message === "Cipher job failed")
      ) {
        throw new Error(CRYPTO_ERROR.SYMMETRIC.WRONG_KEY);
      }

      throw error;
    }

    return Buffer.from(plaintextBuffer).toString();
  },

  /**
   * Returns a hash of the data.
   * 
   * @param data - data to hash
   * @returns hash
   */
  async hash(data: string): Promise<string> {
    if (typeof data !== "string") {
      throw new Error(CRYPTO_ERROR.HASH.INVALID_STRING);
    }

    const hashBuffer = await WebCrypto.subtle.digest(
      CRYPTO_CONFIG.HASH.algorithm,
      Buffer.from(data)
    );

    return Buffer.from(hashBuffer).toString("base64");
  },

  /**
	 * Returns a json web key representation of the key.
	 * This operation is for **symmetric** and **asymmetric** key cryptography.
	 *
	 * @param key - key to export
	 * @returns json web key
	 */
  async exportKey(key: Key): Promise<RawKey> {
    if (!KeyHelper.isKey(key)) {
      throw new Error(CRYPTO_ERROR.COMMON.INVALID_KEY);
    }

    const jsonKey: JsonWebKey = await WebCrypto.subtle.exportKey(
      "jwk",
      key.crypto
    );

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
    };
  },

  /**
	 * Returns a key from the json web key representation.
	 * This operation is for **symmetric** and **asymmetric** key cryptography.
	 *
	 * @param rawKey - json web key to import
	 * @returns key
	 */
  async importKey(
    rawKey: RawKey
  ): Promise<SecretKey | PassKey | PrivateKey | PublicKey> {
    if (!KeyHelper.isRawKey(rawKey as Key)) {
      throw new Error(CRYPTO_ERROR.RAW.INVALID_KEY);
    }

    if (
      rawKey.type === KeyType.PrivateKey ||
			rawKey.type === KeyType.PublicKey
    ) {
      const asymmetricKey = await WebCrypto.subtle.importKey(
        "jwk",
        rawKey.crypto,
        CRYPTO_CONFIG.ASYMMETRIC.algorithm,
        CRYPTO_CONFIG.ASYMMETRIC.exportable,
        CRYPTO_CONFIG.ASYMMETRIC.usages
      );

      const key = {
        type: rawKey.type,
        domain: rawKey.domain,
        crypto: asymmetricKey
      };

      return rawKey.type === KeyType.PrivateKey
        ? (key as PrivateKey)
        : (key as PublicKey);
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
  },

  /**
 * Returns true if the public keys are the same (deep comparison)
 * 
 * @param key1 - key to compare
 * @param key2 - key to compare
 * @returns boolean
 */
  async isSameKey(key1: Key, key2: Key): Promise<boolean> {
    if(!KeyHelper.isKey(key1) || !KeyHelper.isKey(key2)) {
      throw new Error(CRYPTO_ERROR.COMMON.INVALID_KEY);
    }

    if(KeyHelper.isRawKey(key1) || KeyHelper.isRawKey(key2)) {
      throw new Error(CRYPTO_ERROR.COMMON.KEY_NOT_SUPPORTED);
    }
    
    if (key1.type !== key2.type) {
      return false;
    }

    if (key1.domain !== key2.domain) {
      return false;
    }

    // convert the keys to buffers
    const rawKey1 = await CryptoMod.exportKey(key1);
    const rawKey2 = await CryptoMod.exportKey(key2);

    // compare the json objects
    return JSON.stringify(rawKey1) === JSON.stringify(rawKey2);
  }
};

/**
 * Functions for validating cryptographic keys
 * */
export const KeyHelper = {
  /**
 * Returns true if key is a valid Key
 *
 * @param key - key to check
 * @returns boolean
 */
  isKey(key: Key): boolean {
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
      (key.crypto instanceof WebCrypto.CryptoKey === false && !KeyHelper.isRawKey(key)) // key.crypto is not a valid crypto key or raw key
    ) {
      return false;
    }

    return true;
  },

  /**
 * Returns true if the key is a valid raw key
 *
 * @param key key
 * @returns boolean
 */
  isRawKey(key: Key): boolean {
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
  },

  /**
 * Returns true if key is a valid symmetric key (AES)
 *
 * @param key - key to check
 * @returns boolean
 */
  isSymmetricKey(key: Key): boolean {
    if (!KeyHelper.isKey(key)) {
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
  },

  /**
 * Returns true if key is a valid asymmetric key (ECDH)
 *
 * @param key - key to check
 * @returns boolean
 */
  isAsymmetricKey(key: Key): boolean {
    if (!KeyHelper.isKey(key)) {
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
};