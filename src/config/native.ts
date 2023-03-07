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

const isBrowser = typeof window !== "undefined";

/**
 * The WebCrypto API
 */
export const WebCryptoLib: Crypto = isBrowser
  ? window.crypto
  : (webcrypto as unknown as Crypto);

/**
 * A Buffer encoder/decoder
 */
export const BufferLib: BufferEncoder = isBrowser
  ? ({
    toBuffer: (input, encoding) => {
      return encoding === "base64"
        ? new Uint8Array(
          atob(input)
            .split("")
            .map((char) => char.charCodeAt(0))
        ) // atob(input)
        : new TextEncoder().encode(input);
    },
    toString: (input, encoding) => {
      return encoding === "base64"
        ? btoa(input.toString())
        : new TextDecoder().decode(input);
    }
  } as BufferEncoder)
  : ({
    toBuffer: (input, encoding) => {
      return encoding === "base64"
        ? Buffer.from(input, "base64")
        : Buffer.from(input);
    },
    toString: (input, encoding) => {
      return encoding === "base64"
        ? Buffer.from(input).toString("base64")
        : Buffer.from(input).toString();
    }
  } as BufferEncoder);
