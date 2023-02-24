import { webcrypto as WebCrypto } from "crypto"
import { CRYPTO_ERROR } from "../config/messages";
import { CRYPTO_CONFIG } from "../config/algorithm";
import { Ciphertext } from "../interfaces/ciphertext-interface";
import { KeyType, JsonWebKey, Key, RawKey, SecretKey, PassKey, PrivateKey, PublicKey, SharedKey } from "../interfaces/key-interface"
import { KeyValidator } from "./validator-util";

export interface GenKeyParams {
  /**
   * domain to generate the key for
   */
  domain?: string;
}

export interface GenPassKeyParams extends GenKeyParams {
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

export interface GenPublicKeyParams extends GenKeyParams {
  /**
   * private source key
   */
  privateKey: PrivateKey;
}

export interface GenSharedKeyParams extends GenKeyParams {
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
 * Functions for performing symmetric and asymmetric cryptographic operations
 */
export const CryptoUtil = {
  /**
   * Returns a cipher text which is the result of encrypting the plaintext with the key.
   * This operation is for **symmetric** key cryptography.
   * 
   * @param key - crypto key
   * @param plaintext - plain text to encrypt
   * @returns ciphertext
   */
  async encrypt(key: SecretKey | PassKey | SharedKey, plaintext: string): Promise<Ciphertext> {
    if (!KeyValidator.isSymmetricKey(key)) {
      throw new Error(CRYPTO_ERROR.SYMMETRIC.INVALID_KEY);
    }

    if(typeof plaintext !== "string") {
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
      salt: salt
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
    if (!KeyValidator.isSymmetricKey(key)) {
      throw new Error(CRYPTO_ERROR.SYMMETRIC.INVALID_KEY);
    }

    // throw error if ciphertext is not a valid ciphertext
    if(!ciphertext || !ciphertext.data || !ciphertext.salt) {
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
   * Returns a json web key representation of the key.
   * This operation is for **symmetric** and **asymmetric** key cryptography.
   *
   * @param key - key to export
   * @returns json web key
   */
  async exportKey(key: Key): Promise<RawKey> {
    if(!KeyValidator.isKey(key)) {
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

  /**
   * Returns a key from the json web key representation.
   * This operation is for **symmetric** and **asymmetric** key cryptography.
   *
   * @param jsonWebKey - json web key to import
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