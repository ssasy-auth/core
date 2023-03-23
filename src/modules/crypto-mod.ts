import { WebCryptoLib, BufferUtil } from "../utils";
import {
  CRYPTO_CONFIG,
  IV_LENGTH,
  NONCE_LENGTH 
} from "../config";
import type {
  Ciphertext,
  SecretKey,
  PassKey,
  PrivateKey,
  PublicKey,
  SharedKey 
} from "../interfaces";
import { KeyType } from "../interfaces";
import { KeyChecker, KeyModule } from "./key-mod";

enum CryptoErrorCode {
  OPERATION_ERROR = "OperationError", // the operation cannot be performed
  INVALID_ACCESS_ERROR = "InvalidAccessError", // the key used is not allowed to perform the operation (e.g. wrong key type)
}

/**
 * Error messages for the crypto operations
 */
export const CRYPTO_ERROR_MESSAGE = {
  INVALID_SYMMETRIC_KEY: "Key is not a valid symmetric key (AES)",
  INVALID_PLAINTEXT: "Plaintext is not a string",
  INVALID_CIPHERTEXT: "Ciphertext is not valid Ciphertext object",
  INVALID_HASH_STRING: "Input is not a valid string",
  INVALID_SIGNATURE_KEY: "Key is not a private key (ECDH)",
  WRONG_KEY: "The key provided does not match the key used to obfuscate the data",
  MISSING_PASSPHRASE_SALT: "Passphrase salt is missing from ciphertext"
}

/**
 * Operations for encrypting, decrypting and hashing data.
 */
export const CryptoModule = {
  /**
   * Returns a ciphertext which is the result of encrypting the plaintext with the key.
   * This operation is for **symmetric** key cryptography.
   * 
   * @param key - crypto key
   * @param plaintext - plain text to encrypt
   * @param sender - sender public key (optional for shared key)
   * @param recipient - recipient public key (optional for shared key)
   * @returns ciphertext
   */
  async encrypt(key: SecretKey | PassKey | SharedKey | string, plaintext: string, sender?: PublicKey, recipient?: PublicKey): Promise<Ciphertext> {
    
    if (typeof key !== "string" && !KeyChecker.isSymmetricKey(key)) {
      throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_SYMMETRIC_KEY);
    }
    
    if (typeof plaintext !== "string") {
      throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_PLAINTEXT);
    }

    // generate passkey if key is a passphrase
    if(typeof key === "string") {
      key = await KeyModule.generatePassKey({
        passphrase: key 
      });
    }

    // convert plaintext to buffer (string > utf8 > base64 > array buffer)
    const plaintextUtf8Buffer = BufferUtil.StringToBuffer(plaintext, "utf8");
    const plaintextBase64Buffer = BufferUtil.StringToBuffer(BufferUtil.BufferToString(plaintextUtf8Buffer), "base64");

    // initialization vector
    const buffer = BufferUtil.createBuffer(IV_LENGTH);
    const initializationVector = WebCryptoLib.getRandomValues(buffer);

    // encrypt plaintext (returns an Array Buffer)
    const ciphertextBuffer = await WebCryptoLib.subtle.encrypt(
      {
        ...CRYPTO_CONFIG.SYMMETRIC.algorithm,
        iv: initializationVector
      },
      key.crypto,
      plaintextBase64Buffer
    );

    // convert iv to base64 string
    const ivString = BufferUtil.BufferToString(initializationVector);
    // convert salt to base64 string
    const saltString = (key as PassKey).salt ? (key as PassKey).salt : undefined; // passkeys store salt as a string
    // convert data to base64 string
    const dataString = BufferUtil.BufferToString(ciphertextBuffer, "base64");

    return {
      data: dataString,
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

    // throw error if key is a string and salt is missing
    if(typeof key === "string" && !ciphertext.salt) {
      throw new Error(CRYPTO_ERROR_MESSAGE.MISSING_PASSPHRASE_SALT);
    }

    // throw error if key is not a symmetric (secret, shared or passkey)
    if (typeof key !== "string" && !KeyChecker.isSymmetricKey(key)) {
      throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_SYMMETRIC_KEY);
    }

    // generate passkey if key is a passphrase
    if(typeof key === "string") {
      key = await KeyModule.generatePassKey({
        passphrase: key, salt: ciphertext.salt
      })
    }

    // convert iv to buffer
    const ivBuffer = BufferUtil.StringToBuffer(ciphertext.iv);
    // convert data to buffer (base64 > buffer)
    const ciphertextBuffer = BufferUtil.StringToBuffer(ciphertext.data, "base64");

    let plaintextBuffer: Uint8Array;
    
    try {
      const buffer = await WebCryptoLib.subtle.decrypt(
        {
          ...CRYPTO_CONFIG.SYMMETRIC.algorithm,
          iv: ivBuffer
        },
        key.crypto,
        ciphertextBuffer
      );

      // convert buffer to buffer view
      plaintextBuffer = new Uint8Array(buffer);
    } catch (e) {
      const error = e as Error;

      if(error.name === CryptoErrorCode.INVALID_ACCESS_ERROR || error.message === "Cipher job failed"){
        throw new Error(CRYPTO_ERROR_MESSAGE.WRONG_KEY);
      }

      else if (error.name === CryptoErrorCode.OPERATION_ERROR) {
        throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_CIPHERTEXT)
      }

      else {
        throw error; 
      }
    }

    // convert buffer to string (buffer > base64 > utf8 > string)
    const base64String = BufferUtil.BufferToString(plaintextBuffer, "base64");
    return BufferUtil.BufferToString(BufferUtil.StringToBuffer(base64String, "base64"), "utf8");
  },

  /**
   * Takes a message and a private key and returns a signature. Since the webcrypto API 
   * does not support signing with an ECDH key, we use the following workaround:
   * - generate a shared key from the private key and the public key
   * - encrypt the message with the shared key
   * - the signature is the encrypted message
   * 
   * @param privateKey - private key
   * @param message - message to sign
   * @returns ciphertext (signature)
   */
  async sign(privateKey: PrivateKey, message: string): Promise<Ciphertext> {

    if(!KeyChecker.isAsymmetricKey(privateKey) || privateKey.type !== KeyType.PrivateKey) {
      throw new Error(CRYPTO_ERROR_MESSAGE.INVALID_SIGNATURE_KEY);
    }

    // extract shared key from private key
    const publicKey = await KeyModule.generatePublicKey({
      privateKey: privateKey 
    });
    const sharedKey = await KeyModule.generateSharedKey({
      privateKey: privateKey,
      publicKey: publicKey
    });
    
    // return encrypted message
    return await this.encrypt(sharedKey, message);
  },

  /**
   * Takes a signature and a private key and returns true if the signature is valid.
   * 
   * @param privateKey - private key used to sign the message
   * @param ciphertext - signature to verify
   * @returns boolean
   */
  async verify(privateKey: PrivateKey, ciphertext: Ciphertext): Promise<boolean> {
    // extract secret key from private key
    const publicKey = await KeyModule.generatePublicKey({
      privateKey: privateKey
    });
    const sharedKey = await KeyModule.generateSharedKey({
      privateKey: privateKey,
      publicKey: publicKey
    });

    try {
      await this.decrypt(sharedKey, ciphertext);
      return true;
    } catch (e) {
      return false;
    }
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

    // convert data to buffer (string > utf8 > base64 > array buffer)
    const utf8Encoding = BufferUtil.StringToBuffer(data, "utf8");
    const base64Encoding = BufferUtil.StringToBuffer(BufferUtil.BufferToString(utf8Encoding), "base64");

    const hashBuffer = await WebCryptoLib.subtle.digest(
      CRYPTO_CONFIG.HASH.algorithm,
      base64Encoding
    );

    // convert array buffer to string
    return BufferUtil.BufferToString(hashBuffer);
  },

  /**
	 * Returns a random nonce
	 * @returns nonce
	 */
  generateNonce(): Uint8Array {
    // create buffer
    const buffer = BufferUtil.createBuffer(NONCE_LENGTH)

    return WebCryptoLib.getRandomValues(buffer);
  }
};

export const CryptoChecker = {
  /**
   * Checks if the input is a valid ciphertext.
   * 
   * @param input - input to check
   * @returns boolean
   * */
  isCiphertext(input: object): boolean {
    if(!input) return false;

    // input must be an object
    if( typeof input !== "object") return false;

    const ciphertext = input as Ciphertext;

    // data must be present and must be a string
    if( !ciphertext.data || typeof ciphertext.data !== "string") return false;

    // iv must be present and must be a string
    if( !ciphertext.iv || typeof ciphertext.iv !== "string") return false;

    try {
      // data must be buffer-like
      if(!BufferUtil.isBufferString(ciphertext.data)) return false;
      
      // iv must be buffer-like
      if(!BufferUtil.isBufferString(ciphertext.iv)) return false;
  
      if(ciphertext.salt !== undefined) {

        // salt must be a string
        if(typeof ciphertext.salt !== "string") return false;

        // salt must be buffer-like
        if(!BufferUtil.isBufferString(ciphertext.salt)) return false;
      }

      if(ciphertext.sender !== undefined) {
        // sender must be an asymmetric key
        if(!KeyChecker.isAsymmetricKey(ciphertext.sender)) return false;

        // sender must be a public key
        if((ciphertext.sender as unknown as PublicKey).type !== KeyType.PublicKey) return false;
      }

      if(ciphertext.recipient !== undefined) {
        // recipient must be an asymmetric key
        if(!KeyChecker.isAsymmetricKey(ciphertext.recipient)) return false;

        // recipient must be a public key
        if((ciphertext.recipient as unknown as PublicKey).type !== KeyType.PublicKey) return false;
      }
    } catch (error) {
      return false;
    }

    return true;
  }
};