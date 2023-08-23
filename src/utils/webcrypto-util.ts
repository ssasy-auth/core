/**
 * This utility file provides buffer operations on top of 
 * the native APIs based on the environment (browser or Node.js).
 */

import { webcrypto } from "crypto";

const isBrowser = typeof window !== "undefined";

/**
 * The WebCrypto API.
 * 
 * References different WebCrypto APIs based on the environment (browser or Node.js).
 */
export const WebCryptoLib: Crypto = isBrowser
  ? window.crypto
  : (webcrypto as unknown as Crypto);
