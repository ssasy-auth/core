import { Key } from "./key-interface";

/**
 * @interface Wallet
 * @description Manage cryptographic keys
 */
export interface Wallet {
  /**
   * Set of keys
   * */
  keys: Key[];

  /**
   * Sets the keys, if any, in the wallet
   * @returns nothing
   */
  _init: () => Promise<void>;

  /**
   * Returns wallet keys
   * 
   * @returns keys
   */
  getKeys: () => Promise<Key[]>;

  /**
   * Returns a key from the wallet
   * 
   * @param domain key domain
   */
  getKey(domain: string): Promise<Key>;
}
