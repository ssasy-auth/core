/**
 * The purpose of this file is to provide a single place to import the native
 * APIs based on the environment (browser or Node.js).
 */

import { webcrypto } from "crypto";

type Encoding = "utf8" | "base64";

interface BufferEncoder {
  /**
   * Returns a buffer from a string
   * 
   * @param input - The string to encode
   * @returns buffer
   */
  toBuffer: (input: string, encoding?: Encoding) => Uint8Array | ArrayBuffer;

  /**
   * Returns a string from a buffer
   * 
   * @param input - The buffer to decode
   * @returns string
   */
  toString: (input: Uint8Array | ArrayBuffer, encoding?: Encoding) => string;
}

/* Libraries to export */
/**
 * The WebCrypto API
 */
let WebCryptoLib: Crypto;
/**
 * A Buffer encoder/decoder
 */
let BufferLib: BufferEncoder;

const isBrowser = typeof window !== "undefined";

if (isBrowser) {

  if (!window.crypto) {
    WebCryptoLib = window.crypto;
  }

  BufferLib = {
    toBuffer: (input, encoding) => {
      return encoding === "base64" 
        ? new Uint8Array(atob(input).split("")
          .map(char => char.charCodeAt(0))) // atob(input) 
        : new TextEncoder().encode(input);
    },
    toString: (input, encoding) => {
      return encoding === "base64" 
        ? btoa(input.toString()) 
        : new TextDecoder().decode(input);
    }
  } as BufferEncoder;

} else {

  // Cast to `any` to avoid TypeScript errors since `webcrypto` is not available in Node.js by default
  WebCryptoLib = webcrypto as unknown as Crypto;

  BufferLib = {
    toBuffer: (input, encoding) => {
      return encoding === "base64" 
        ? Buffer.from(input, "base64") 
        : Buffer.from(input)
    },
    toString: (input, encoding) => {
      return encoding === "base64" 
        ? Buffer.from(input).toString("base64") 
        : Buffer.from(input).toString()
    }
  } as BufferEncoder;
}

export { WebCryptoLib, BufferLib };
