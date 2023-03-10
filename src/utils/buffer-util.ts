/**
 * This utility file provides buffer operations on top of 
 * the native APIs based on the environment (browser or Node.js).
 */

import { IV_LENGTH } from "../config";

const isBrowser = typeof window !== "undefined";

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
   * @param encoding - The encoding to use
	 * @returns string
	 */
	toString: (input: Uint8Array | ArrayBuffer, encoding?: Encoding) => string;
}

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


export function isStringUint8Array(base64String: string): boolean {
  try {
    // convert base64 string to valid buffer (uint8array)
    const buffer = BufferLib.toBuffer(base64String, "base64");
    
    return (buffer as Uint8Array).length === IV_LENGTH;
  } catch (error) {
    return false;
  }
}