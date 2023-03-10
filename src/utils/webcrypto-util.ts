/**
 * This utility file provides buffer operations on top of 
 * the native APIs based on the environment (browser or Node.js).
 */

import { webcrypto } from "crypto";

const isBrowser = typeof window !== "undefined";

/**
 * The WebCrypto API
 */
export const WebCryptoLib: Crypto = isBrowser
  ? window.crypto
  : (webcrypto as unknown as Crypto);
