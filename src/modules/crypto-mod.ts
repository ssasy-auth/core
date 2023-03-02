import { webcrypto as WebCrypto } from "crypto";
import { CRYPTO_CONFIG } from "../../src/config/algorithm";
import { Ciphertext } from "../interfaces/ciphertext-interface";
import { Key, SecretKey, PassKey, PublicKey, SharedKey } from "../interfaces/key-interface";
import { KeyChecker, KeyModule } from "./key-mod";

/**
 * Error messages for the crypto operations
 */
export const CRYPTO_ERROR_MESSAGE = {
  INVALID_SYMMETRIC_KEY: "Key is not a valid symmetric key (AES)",
  INVALID_PLAINTEXT: "Plaintext is not a string",
  INVALID_CIPHERTEXT: "Ciphertext is not valid Ciphertext object",
  INVALID_HASH_STRING: "Input is not a valid string",
  WRONG_KEY: "The key provided does not match the key used to obfuscate the data",
  MISSING_PASSPHRASE_SALT: "Passphrase salt is missing from ciphertext"
}

/**
 * Operations for encrypting, decrypting and hashing data.
 */
export const CryptoModule = {
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
  async encrypt(key: SecretKey | PassKey | SharedKey | string, plaintext: string, sender?: PublicKey, recipient?: PublicKey): Promise<Ciphertext> {
    let encryptionKey: Key;

    if(typeof key === "string") {
      encryptionKey = await KeyModule.generatePassKey({ passphrase: key });
    } else {
      if (!KeyChecker.isSymmetricKey(key)) {
        throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_SYMMETRIC_KEY);
      }

      encryptionKey = key;
    }
    
    if (typeof plaintext !== "string") {
      throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_PLAINTEXT);
    }

    // initialization vector
    const initializationVector = WebCrypto.getRandomValues(new Uint8Array(12));

    // encrypt plaintext
    const ciphertextBuffer = await WebCrypto.subtle.encrypt(
      {
        ...CRYPTO_CONFIG.SYMMETRIC.algorithm,
        iv: initializationVector
      },
      encryptionKey.crypto,
      Buffer.from(plaintext)
    );

    return {
      data: Buffer.from(ciphertextBuffer).toString("base64"),
      iv: initializationVector,
      salt: (encryptionKey as PassKey).salt,
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
  async decrypt(key: SecretKey | PassKey | SharedKey | string, ciphertext: Ciphertext): Promise<string> {
    // throw error if ciphertext is not a valid ciphertext
    if (!ciphertext || !ciphertext.data || !ciphertext.iv) {
      throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    let decryptionKey: Key;

    if(typeof key === "string") {
      if(!ciphertext.salt) {
        throw new Error(CRYPTO_ERROR_MESSAGE.MISSING_PASSPHRASE_SALT);
      }

      decryptionKey = await KeyModule.generatePassKey({ passphrase: key, salt: ciphertext.salt });
    } else {
    // throw error if key is not a shared or pass key
      if (!KeyChecker.isSymmetricKey(key)) {
        throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_SYMMETRIC_KEY);
      }
      
      decryptionKey = key;
    }

    let plaintextBuffer: ArrayBuffer;

    try {
      plaintextBuffer = await WebCrypto.subtle.decrypt(
        {
          ...CRYPTO_CONFIG.SYMMETRIC.algorithm,
          iv: ciphertext.iv
        },
        decryptionKey.crypto,
        Buffer.from(ciphertext.data, "base64")
      );
    } catch (error) {
      if (
        error instanceof Error &&
        (error.name === "InvalidAccessError" || error.message === "Cipher job failed")
      ) {
        throw new Error(CRYPTO_ERROR_MESSAGE.WRONG_KEY);
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
      throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_HASH_STRING);
    }

    const hashBuffer = await WebCrypto.subtle.digest(
      CRYPTO_CONFIG.HASH.algorithm,
      Buffer.from(data)
    );

    return Buffer.from(hashBuffer).toString("base64");
  }
};
