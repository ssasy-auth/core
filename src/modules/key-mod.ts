import { BufferUtil, WebCryptoLib } from "../utils";
import { CRYPTO_ALGORITHMS, CRYPTO_CONFIG, SALT_LENGTH } from "../config";
import type {
  GenericKey,
  JsonWebKey,
  PassKey,
  PrivateKey,
  PublicKey,
  RawKey,
  SecretKey,
  SecureContextKey,
  SharedKey 
} from "../interfaces";
import { KeyType } from "../interfaces";

export const KEY_ERROR_MESSAGE = {
  INVALID_PASSPHRASE: "Passphrase is not a valid string",
  INVALID_PASSPHRASE_SALT: "Passphrase salt is not a valid string based Uint8Array",
  INVALID_ASYMMETRIC_KEY: "Key is not a valid asymmetric key (ECDH)",
  INVALID_PRIVATE_KEY: "Key is not a private key",
  INVALID_PUBLIC_KEY: "Key is not a public key",
  INVALID_KEY: "Key is not a valid key instance",
  INVALID_RAW_KEY: "Key is not a valid raw key",
  DUPLICATE_SHARED_KEY_PARAMS: "Cannot generate a shared key with the same key type" 
};

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
	 *
	 * Note: although the `salt` is stored as a string, it is a
	 * base64 encoded Uint8Array and should be converted to
	 * a Uint8Array before use.
	 */
	salt?: string;

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
 * Operations for generating symmetric and asymmetric keys
 */
export const KeyModule = {
  /**
	 * Returns a symmetric key (AES-GCM)
	 * 
   * Note: This operation is for **symmetric** key cryptography.
	 *
	 * @returns secret key
	 * */
  async generateKey(params?: GenKeyParams): Promise<SecretKey> {
    const cryptoKey = await WebCryptoLib.subtle.generateKey(
      CRYPTO_CONFIG.SYMMETRIC.algorithm,
      CRYPTO_CONFIG.SYMMETRIC.exportable,
      CRYPTO_CONFIG.SYMMETRIC.usages
    ) as CryptoKey;

    return {
      type: KeyType.SecretKey,
      domain: params?.domain,
      crypto: cryptoKey 
    };
  },

  /**
	 * Returns a symmetric key (AES-GCM) that is derived from a passphrase.
	 * 
   * Note: This operation is for **symmetric** key cryptography.
	 *
	 * @returns password key
	 * */
  async generatePassKey(params: GenPassKeyParams): Promise<PassKey> {
    const { domain, passphrase, salt, iterations } = params;

    if (typeof passphrase !== "string") {
      throw new Error(KEY_ERROR_MESSAGE.INVALID_PASSPHRASE);
    }

    if (salt && typeof salt !== "string") {
      throw new Error(KEY_ERROR_MESSAGE.INVALID_PASSPHRASE_SALT);
    }

    // convert passphrase to buffer
    const passphraseBuffer = BufferUtil.StringToBuffer(passphrase);

    // prepare key material for PBKDF2
    const keyMaterial = await WebCryptoLib.subtle.importKey(
      "raw",
      passphraseBuffer,
      CRYPTO_ALGORITHMS.PBKDF2.name,
      false,
      [ "deriveBits", "deriveKey" ]
    );

    // if salt exists, convert to buffer otherwise generate random salt
    const saltBuffer = salt
      ? BufferUtil.StringToBuffer(salt)
      : WebCryptoLib.getRandomValues(BufferUtil.createBuffer(SALT_LENGTH));

    // prepare iterations for key with provided iterations or use default iterations
    const keyIterations = iterations || CRYPTO_ALGORITHMS.PBKDF2.iterations;

    // generate key from key material
    const cryptoKey = await WebCryptoLib.subtle.deriveKey(
      {
        ...CRYPTO_ALGORITHMS.PBKDF2,
        salt: saltBuffer,
        iterations: keyIterations 
      },
      keyMaterial,
      CRYPTO_CONFIG.SYMMETRIC.algorithm,
      CRYPTO_CONFIG.SYMMETRIC.exportable,
      CRYPTO_CONFIG.SYMMETRIC.usages
    );

    // convert salt to base64 string
    const saltString = BufferUtil.BufferToString(saltBuffer);

    return {
      type: KeyType.PassKey,
      domain: domain,
      crypto: cryptoKey,
      salt: saltString,
      iterations: keyIterations,
      hash: CRYPTO_ALGORITHMS.PBKDF2.hash 
    };
  },

  /**
	 * Returns a private key (ECDH).
	 * 
   * Note: This operation is for **asymmetric** key cryptography.
	 *
	 * @returns private key
	 * */
  async generatePrivateKey(params?: GenKeyParams): Promise<PrivateKey> {
    const { privateKey } = await WebCryptoLib.subtle.generateKey(
      CRYPTO_CONFIG.ASYMMETRIC.algorithm,
      CRYPTO_CONFIG.ASYMMETRIC.exportable,
      CRYPTO_CONFIG.ASYMMETRIC.usages
    ) as CryptoKeyPair;

    return {
      type: KeyType.PrivateKey,
      domain: params?.domain,
      crypto: privateKey 
    };
  },

  /**
	 * Returns a public key (ECDH) derived from a private key (ECDH). 
   * 
	 * Note: This operation is for **asymmetric** key cryptography.
	 *
	 * @returns public key
	 */
  async generatePublicKey(params: GenPublicKeyParams): Promise<PublicKey> {
    const { domain, privateKey } = params;

    if (!KeyChecker.isAsymmetricKey(privateKey)) {
      throw new Error(KEY_ERROR_MESSAGE.INVALID_ASYMMETRIC_KEY);
    }

    if (privateKey.type !== KeyType.PrivateKey) {
      throw new Error(KEY_ERROR_MESSAGE.INVALID_PRIVATE_KEY);
    }

    // convert private key to public key
    const privateJsonWebKey = await WebCryptoLib.subtle.exportKey(
      "jwk",
      privateKey.crypto
    );

    // delete private key property to convert to public key
    delete privateJsonWebKey.d;

    const publicKey = await WebCryptoLib.subtle.importKey(
      "jwk",
      privateJsonWebKey,
      CRYPTO_CONFIG.ASYMMETRIC.algorithm,
      CRYPTO_CONFIG.ASYMMETRIC.exportable,
      [] // no usages for public key
    );

    return {
      type: KeyType.PublicKey,
      domain: domain,
      crypto: publicKey 
    };
  },

  /**
	 * Returns a shared key (AES-GCM) derived from a private key belonging
   * to one party and the public key of another party.
	 * 
   * Note: This operation is for **asymmetric** key cryptography.
	 *
	 * @returns shared key
	 */
  async generateSharedKey(params: GenSharedKeyParams): Promise<SharedKey> {
    const { domain, privateKey, publicKey } = params;

    if (!KeyChecker.isAsymmetricKey(privateKey)) {
      throw new Error(KEY_ERROR_MESSAGE.INVALID_PRIVATE_KEY);
    }

    if (!KeyChecker.isAsymmetricKey(publicKey)) {
      throw new Error(KEY_ERROR_MESSAGE.INVALID_PUBLIC_KEY);
    }

    if ((privateKey as GenericKey).type === (publicKey as GenericKey).type) {
      throw new Error(KEY_ERROR_MESSAGE.DUPLICATE_SHARED_KEY_PARAMS);
    }

    const sharedKey = await WebCryptoLib.subtle.deriveKey(
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
	 * Returns a raw key object (JSON Web Key) from a key instance.
   * 
   * Properties like key value, key length, key type, etc. cannot be accessed
   * in the key instance for security reasons. Converting the key instance to
   * a raw key object allows you to access these properties. This is necessary
   * when saving a key for long-term storage or outside of runtime memory.
   * 
   * Warning: The raw key object exposes sensitive information and should be 
   * handled with care.
	 * 
   * Note: This operation is for **symmetric** and **asymmetric** key cryptography.
	 *
	 * @param key - key to export
	 * @returns json web key
	 */
  async exportKey(key: GenericKey): Promise<RawKey> {
    if (!KeyChecker.isKey(key)) {
      throw new Error(KEY_ERROR_MESSAGE.INVALID_KEY);
    }

    if(KeyChecker.isRawKey(key)) {
      return key as RawKey;
    }

    const jsonKey: JsonWebKey = await WebCryptoLib.subtle.exportKey(
      "jwk",
      (key as SecureContextKey).crypto
    ) as JsonWebKey;

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
	 * Returns a key instance from the raw key object (JSON Web Key).
   * 
   * The WebCrypto API only accepts key instances as input for cryptographic
   * operations like encryption, decryption, signing, etc. Converting the raw
   * key object to a key instance allows you to use the key for cryptographic
   * operations again.
	 * 
   * Note: This operation is for **symmetric** and **asymmetric** key cryptography.
	 *
	 * @param rawKey - json web key to import
	 * @returns key
	 */
  async importKey(
    rawKey: RawKey
  ): Promise<SecretKey | PassKey | PrivateKey | PublicKey> {
    if (!KeyChecker.isRawKey(rawKey as GenericKey)) {
      throw new Error(KEY_ERROR_MESSAGE.INVALID_RAW_KEY);
    }

    if (
      rawKey.type === KeyType.PrivateKey ||
			rawKey.type === KeyType.PublicKey
    ) {

      // see -> https://github.com/this-oliver/ssasy/issues/10
      const keyUsages: KeyUsage[] = rawKey.type === KeyType.PrivateKey ? CRYPTO_CONFIG.ASYMMETRIC.usages : [];

      const asymmetricKey = await WebCryptoLib.subtle.importKey(
        "jwk",
        rawKey.crypto,
        CRYPTO_CONFIG.ASYMMETRIC.algorithm,
        CRYPTO_CONFIG.ASYMMETRIC.exportable,
        keyUsages
      );

      const key = {
        type: rawKey.type,
        domain: rawKey.domain,
        crypto: asymmetricKey 
      };

      return rawKey.type === KeyType.PrivateKey
        ? (key as PrivateKey)
        : (key as PublicKey);
    } 
    
    else {
      const cryptoKey = await WebCryptoLib.subtle.importKey(
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
          hash: rawKey.hash,
          salt: rawKey.salt,
          iterations: rawKey.iterations 
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

/**
 * Operations for validating cryptographic keys
 * */
export const KeyChecker = {
  /**
	 * Returns true if key is a valid.
	 *
	 * @param key - key to check
	 * @returns boolean
	 */
  isKey(key: GenericKey): boolean {
    if (!key) {
      return false;
    }

    // return false if key type is not present or is not a valid key type
    if (!key.type || !Object.values(KeyType).includes(key.type)) {
      return false;
    }

    /**
     * Returns true if the object is a valid WebCrypto CryptoKey.
     * 
     * @param obj - object to check
     * @returns boolean
     */
    function _isCryptoKey(obj: unknown): boolean {
      return (
        typeof obj === "object" &&
				obj !== null &&
				typeof (obj as CryptoKey).type === "string" &&
				typeof (obj as CryptoKey).algorithm === "object" &&
				typeof (obj as CryptoKey).extractable === "boolean" &&
				typeof (obj as CryptoKey).usages === "object" &&
				typeof (obj as CryptoKey).algorithm.name === "string"
      );
    }

    // return false if key crypto is not present or is not a valid crypto key
    if (
      !key.crypto || // key.crypto is not present
			(!_isCryptoKey(key.crypto) && !KeyChecker.isRawKey(key)) // key.crypto is not a valid crypto key or raw key
    ) {
      return false;
    }

    return true;
  },

  /**
	 * Returns true if the key is raw (JSON Web Key)
	 *
	 * @param key key
	 * @returns boolean
	 */
  isRawKey(key: GenericKey): boolean {
    if (!key) {
      return false;
    }

    // return false if key does not have crypto property
    if (!key.crypto) {
      return false;
    }

    const crypto = key.crypto as JsonWebKey;

    /**
     * Checks if the key is a symmetric key (AES) and whether it has the required properties (k)
     */
    const isValidSymmetricKey: boolean = (
      crypto.kty === CRYPTO_ALGORITHMS.AES.jwk.kty && 
      crypto.k !== undefined
    );
    
    /**
     * Checks if the key is an asymmetric key (EC) and whether it has the required properties (x, y). 
     * 
     * note: this does not fully validate private asymmetric keys
     */
    const isValidAsymmetricKey: boolean = (
      crypto.kty === CRYPTO_ALGORITHMS.ECDH.jwk.kty && 
      crypto.x !== undefined && 
      crypto.y !== undefined
    );
    
    /**
     * Checks if the key is a valid symmetric or asymmetric key
     */
    const isValidKey: boolean = (
      crypto.kty !== undefined &&
      crypto.key_ops !== undefined &&
      (isValidSymmetricKey || isValidAsymmetricKey)
    );

    return isValidKey;
  },

  /**
	 * Returns true if key is a symmetric (AES)
	 *
	 * @param key - key to check
	 * @returns boolean
	 */
  isSymmetricKey(key: GenericKey): boolean {
    if (!KeyChecker.isKey(key)) {
      return false;
    }

    if (
      key.type !== KeyType.SecretKey &&
			key.type !== KeyType.PassKey &&
			key.type !== KeyType.SharedKey
    ) {
      return false;
    }

    if(KeyChecker.isRawKey(key)) {
      if((key as RawKey).crypto.alg !== CRYPTO_ALGORITHMS.AES.jwk.algo) {
        return false;
      }
    } else {
      if ((key as SecureContextKey).crypto.algorithm.name !== CRYPTO_ALGORITHMS.AES.name) {
        return false;
      }
    }

    return true;
  },

  /**
	 * Returns true if key is a asymmetric (ECDH)
	 *
	 * @param key - key to check
	 * @returns boolean
	 */
  isAsymmetricKey(key: GenericKey): boolean {
    if (!KeyChecker.isKey(key)) {
      return false;
    }

    if (key.type !== KeyType.PrivateKey && key.type !== KeyType.PublicKey) {
      return false;
    }

    if(KeyChecker.isRawKey(key)) {
      if((key as RawKey).crypto.alg !== CRYPTO_ALGORITHMS.ECDH.jwk.algo) {
        return false;
      }
    } else {
      if ((key as SecureContextKey).crypto.algorithm.name !== CRYPTO_ALGORITHMS.ECDH.name) {
        return false;
      }
    }

    return true;
  },

  /**
	 * Returns true if the keys are the same (deep comparison)
	 *
	 * @param key1 - key to compare
	 * @param key2 - key to compare
	 * @returns boolean
	 */
  async isSameKey(key1: GenericKey, key2: GenericKey): Promise<boolean> {
    if (
      !KeyChecker.isKey(key1) ||
			!KeyChecker.isKey(key2) ||
			KeyChecker.isRawKey(key1) ||
			KeyChecker.isRawKey(key2)
    ) {
      throw new Error(KEY_ERROR_MESSAGE.INVALID_KEY);
    }

    if (key1.type !== key2.type) {
      return false;
    }

    if (key1.domain !== key2.domain) {
      return false;
    }

    // convert the keys to buffers
    const rawKey1 = await KeyModule.exportKey(key1);
    const rawKey2 = await KeyModule.exportKey(key2);

    // compare the json objects
    return JSON.stringify(rawKey1) === JSON.stringify(rawKey2);
  } 
};
