import {
  WebCryptoLib, BufferLib, isStringUint8Array 
} from "../utils";
import { CRYPTO_CONFIG, IV_LENGTH } from "../config";
import type {
  Ciphertext, GenericKey, SecretKey, PassKey, PublicKey, SharedKey 
} from "../interfaces";
import { KeyType } from "../interfaces";
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
    let encryptionKey: GenericKey;

    if(typeof key === "string") {
      encryptionKey = await KeyModule.generatePassKey({
        passphrase: key 
      });
    } else {
      if (!KeyChecker.isSymmetricKey(key)) {
        throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_SYMMETRIC_KEY);
      }

      encryptionKey = key;
    }
    
    if (typeof plaintext !== "string") {
      throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_PLAINTEXT);
    }

    // convert plaintext to buffer
    const plaintextBuffer = BufferLib.toBuffer(plaintext);

    // initialization vector
    const initializationVector = WebCryptoLib.getRandomValues(new Uint8Array(IV_LENGTH));

    // encrypt plaintext
    const ciphertextBuffer = await WebCryptoLib.subtle.encrypt(
      {
        ...CRYPTO_CONFIG.SYMMETRIC.algorithm,
        iv: initializationVector
      },
      encryptionKey.crypto,
      plaintextBuffer
    );

    // convert iv and salt to base64 string
    const ivString = BufferLib.toString(initializationVector, "base64");
    const saltString = (encryptionKey as PassKey).salt ? (encryptionKey as PassKey).salt : undefined; // passkeys store salt as a string

    return {
      data: BufferLib.toString(ciphertextBuffer, "base64"),
      iv: ivString,
      salt: saltString,
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

    // convert iv and salt to buffer
    const ivBuffer = BufferLib.toBuffer(ciphertext.iv, "base64") as Uint8Array;
    

    let decryptionKey: GenericKey;

    if(typeof key === "string" && !ciphertext.salt) {
      // throw error if key is a string and salt is missing
      throw new Error(CRYPTO_ERROR_MESSAGE.MISSING_PASSPHRASE_SALT);

    } else if(typeof key === "string") {
      // convert passphrase to key if key is a string
      decryptionKey = await KeyModule.generatePassKey({
        passphrase: key, salt: ciphertext.salt 
      });

    } 
    else if (!KeyChecker.isSymmetricKey(key)) {
      // throw error if key is not a shared or pass key
      throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_SYMMETRIC_KEY);

    } 
    else {
      // use key if key is a shared or pass key
      decryptionKey = key;

    }

    let plaintextBuffer: ArrayBuffer;

    // convert ciphertextdata to buffer
    const ciphertextBuffer = BufferLib.toBuffer(ciphertext.data, "base64");

    try {
      plaintextBuffer = await WebCryptoLib.subtle.decrypt(
        {
          ...CRYPTO_CONFIG.SYMMETRIC.algorithm,
          iv: ivBuffer
        },
        decryptionKey.crypto,
        ciphertextBuffer
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

    return BufferLib.toString(plaintextBuffer);
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

    const hashBuffer = await WebCryptoLib.subtle.digest(
      CRYPTO_CONFIG.HASH.algorithm,
      BufferLib.toBuffer(data)
    );

    return BufferLib.toString(hashBuffer, "base64");
  }
};

export const CryptoChecker = {
  /**
   * Checks if the input is a valid ciphertext.
   * 
   * @param input - input to check
   * @returns boolean
   * */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  isCiphertext(input: any): boolean {
    if(!input) return false;

    if(typeof input !== "object") return false;

    if(!input.data || !input.iv) return false;

    // return false if iv is not a string
    if(typeof input.iv !== "string") {
      return false;
    }

    // return false if iv is not buffer-like
    if(!isStringUint8Array(input.iv)) {
      return false;
    }

    // return false if data is not a string
    if(typeof input.data !== "string") {
      return false;
    }

    // return false if data is not a base64 string
    const base64Regex = new RegExp("^[a-zA-Z0-9+/]*={0,2}$");
    if(!base64Regex.test(input.data)) {
      return false;
    }

    if(input.salt !== undefined) {

      // return false if salt is not a string
      if(typeof input.salt !== "string") {
        return false;
      }

      // return false if salt is not buffer-like
      if(!isStringUint8Array(input.salt)) {
        return false;
      }
    }

    if(input.sender !== undefined) {
      if(
        !KeyChecker.isAsymmetricKey(input.sender) && 
        (input.sender as unknown as PublicKey).type !== KeyType.PublicKey
      ) {
        return false;
      }
    }

    if(input.recipient !== undefined) {
      if(
        !KeyChecker.isAsymmetricKey(input.recipient) && 
        (input.recipient as unknown as PublicKey).type !== KeyType.PublicKey
      ) {
        return false;
      }
    }

    return true;
  }
};