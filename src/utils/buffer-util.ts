/**
 * @file buffer-util.ts
 * @description This utility file provides buffer operations on top of the native APIs based on the environment (browser or Node.js).
 */

import { Buffer } from "buffer/";

/**
 * Minimum buffer length.
 */
export const DEFAULT_MINIMUM_BUFFER_LENGTH = 12;

/**
 * BufferUtil error messages.
 */
export const BUFFER_ERROR_MESSAGE = {
  MISSING_LENGTH: "Length is required",
  MISSING_BUFFER: "Buffer is required",
  MISSING_BUFFER_STRING: "Buffer string is required",
  MISSING_TEST_STRING: "Test string is required",
  INVALID_BUFFER: "Buffer is not a array buffer or uint8array",
  INVALID_BUFFER_LENGTH: `Buffer length not a number or less than ${DEFAULT_MINIMUM_BUFFER_LENGTH}`,
  INVALID_BUFFER_STRING: "Buffer string is not a valid base64 string",
  INVALID_ENCODING: "Encoding is not a valid encoding (utf8 or base64)" 
};

export type Encoding = "utf8" | "base64";

/**
 * Returns a buffer of the specified length.
 * 
 * @param length - length of the buffer
 * @returns buffer
 */
function createBuffer(length: number): Uint8Array {
  if(!length) {
    throw new Error(BUFFER_ERROR_MESSAGE.MISSING_LENGTH);
  }

  if(typeof length !== "number" || length < DEFAULT_MINIMUM_BUFFER_LENGTH) {
    throw new Error(BUFFER_ERROR_MESSAGE.INVALID_BUFFER_LENGTH);
  }

  return new Uint8Array(length);
}

/**
 * Returns a string that has been converted from a buffer (uint8array or arraybuffer).
 * 
 * Default encoding: `base64`
 * 
 * @param buffer - buffer to convert
 * @returns string
 */
function BufferToString(buffer: Uint8Array | ArrayBuffer, encoding?: Encoding): string {
  if(!buffer) {
    throw new Error(BUFFER_ERROR_MESSAGE.MISSING_BUFFER);
  }

  if(!(buffer instanceof Uint8Array) && !(buffer instanceof ArrayBuffer)) {
    throw new Error(BUFFER_ERROR_MESSAGE.INVALID_BUFFER);
  }
  
  const bufferView: Uint8Array = buffer instanceof ArrayBuffer 
    ? new Uint8Array(buffer) 
    : buffer;

  if(encoding && (encoding !== "utf8" && encoding !== "base64")) {
    throw new Error(BUFFER_ERROR_MESSAGE.INVALID_ENCODING);
  }

  return Buffer.from(bufferView).toString(encoding || "base64");
}

/**
 * Returns a buffer (uint8array) from a base64 string.
 * 
 * Default encoding: `base64`
 * 
 * @param bufferString - buffer string
 * @returns buffer
 */
function StringToBuffer(bufferString: string, encoding?: Encoding): Uint8Array {
  if(!bufferString) {
    throw new Error(BUFFER_ERROR_MESSAGE.MISSING_BUFFER_STRING);
  }

  if(!isBase64String(bufferString) && !isUtf8String(bufferString)) {
    throw new Error(BUFFER_ERROR_MESSAGE.INVALID_BUFFER_STRING);
  }

  if(encoding && (encoding !== "utf8" && encoding !== "base64")) {
    throw new Error(BUFFER_ERROR_MESSAGE.INVALID_ENCODING);
  }

  return Buffer.from(bufferString, encoding || "base64");
}

/**
 * Returns true if string is a valid buffer (uint8array).
 * 
 * @param bufferString - string
 * @returns boolean
 */
export function isBufferString(bufferString: string): boolean {
  if(!bufferString) {
    throw new Error(BUFFER_ERROR_MESSAGE.MISSING_BUFFER_STRING);
  }

  if(!isBase64String(bufferString) && !isUtf8String(bufferString)) {
    return false;
  }

  let buffer;

  try {
    // try converting to buffer as base64
    buffer = StringToBuffer(bufferString, "base64");
  } catch (error) {
    
    try {
      // try converting to buffer as ut8
      buffer = StringToBuffer(bufferString, "utf8");
    } catch (error) {
      return false;
    }
  }
  
  
  return buffer instanceof Uint8Array && buffer.byteLength > 0;
}

/**
 * Returns true if the string is a valid base64 string.
 * 
 * @param bufferString - test string
 * @returns boolean
 */
export function isBase64String(testString: string): boolean {
  if(!testString) {
    throw new Error(BUFFER_ERROR_MESSAGE.MISSING_TEST_STRING);
  }

  const base64Regex = new RegExp("^[a-zA-Z0-9+/]*={0,2}$");
  return base64Regex.test(testString);
}

/**
 * Returns true if the string is a valid utf8 string.
 * 
 * @param testString - test string
 * @returns boolean
 */
export function isUtf8String(testString: string): boolean {
  if(!testString) {
    throw new Error(BUFFER_ERROR_MESSAGE.MISSING_TEST_STRING);
  }
  
  try {
    const encodedUri = encodeURIComponent(testString);
    decodeURIComponent(encodedUri);
    return true;
  } catch (error) {
    return false;
  }
}

export const BufferUtil = {
  createBuffer,
  BufferToString,
  StringToBuffer,
  isBufferString,
  isBase64String,
  isUtf8String 
};
