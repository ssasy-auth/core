import { RawKey, Key } from "./key-interface";

/**
 * @interface Vault
 * @description Stores, retreives and manages cryptographic keys on local storage
 * */
export interface Vault {
  /**
   * Stores a key locally and returns path to the key
   *
   * @param passphrase - passphrase to encrypt the key
   * @param key - key to store
   * @returns path
   * */
  store: (passphrase: string, key: Key) => Promise<string>;

  /**
   * Returns a key from the local store
   *
   * @param passphrase - passphrase to decrypt the key
   * @param path - path to the key
   * @returns key
   * */
  get: (passphrase: string, path: string) => Promise<RawKey>;

  /**
   * Returns true if a file exists at the path
   * @param path - path to the file
   * @returns boolean
   * */
  fileExists: (path: string) => Promise<boolean>;
}
