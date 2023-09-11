/* eslint-disable @typescript-eslint/no-explicit-any */
import { expect } from "chai";
import { TEST_ERROR } from "../config";
import { BUFFER_ERROR_MESSAGE, BufferUtil, DEFAULT_MINIMUM_BUFFER_LENGTH } from "../../src/utils";

function getTestBuffer(): Uint8Array {
  const text = "hello world";
  // convert string to buffer
  return BufferUtil.StringToBuffer(text);
}

describe("[BufferUtils Test Suite]", () => {
  describe("createBuffer()", () => {
    it("should throw an error if length is not specified", () => {
      try {
        BufferUtil.createBuffer(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.MISSING_LENGTH);
      }
    });

    it("should throw an error if length is not a number", () => {
      try {
        BufferUtil.createBuffer("test" as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.INVALID_BUFFER_LENGTH);
      }
    });

    it("should throw an error if length is less than DEFAULT_MINIMUM_BUFFER_LENGTH", () => {
      try {
        BufferUtil.createBuffer(DEFAULT_MINIMUM_BUFFER_LENGTH - 1);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.INVALID_BUFFER_LENGTH);
      }
    });

    it("should return a buffer with specified length", () => {
      const lengths = [ 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 ];

      for (const length of lengths) {
        const buffer = BufferUtil.createBuffer(length);
        expect(buffer.byteLength).to.equal(length);
      }
    });
    
    it("should return a buffer with the uint8array type", () => {
      const buffer = getTestBuffer();
      expect(buffer instanceof Uint8Array).to.be.true;
    });
  });

  describe("BufferToString()", () => {
    it("should throw an error if buffer is not specified", () => {
      try {
        BufferUtil.BufferToString(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.MISSING_BUFFER);
      }
    });

    it("should throw an error if buffer is not array buffer or uint8array", () => {
      try {
        BufferUtil.BufferToString("test" as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.INVALID_BUFFER);
      }

      try {
        BufferUtil.BufferToString(123 as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.INVALID_BUFFER);
      }

      try {
        BufferUtil.BufferToString([ 1, 2, 3 ] as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.INVALID_BUFFER);
      }

      try {
        const buffer = new Uint16Array(8);
        BufferUtil.BufferToString(buffer as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.INVALID_BUFFER);
      }
    });

    it("should return a base64 string if encoding is not specififed", () => {
      const buffer = getTestBuffer();
      const bufferString = BufferUtil.BufferToString(buffer);
      expect(bufferString).to.be.a("string");

      const result = BufferUtil.isBase64String(bufferString);
      expect(result).to.be.true;
    });

    it("should return a base64 string if encoding is specified as base64", () => {
      const buffer = getTestBuffer();
      const bufferString = BufferUtil.BufferToString(buffer, "base64");
      expect(bufferString).to.be.a("string");

      const result = BufferUtil.isBase64String(bufferString);
      expect(result).to.be.true;
    });

    it("should return a utf8 string if encoding is specified as utf8", () => {
      const buffer = getTestBuffer();
      const bufferString = BufferUtil.BufferToString(buffer, "utf8");
      expect(bufferString).to.be.a("string");

      const result = BufferUtil.isUtf8String(bufferString);
      expect(result).to.be.true;
    });
  });

  describe("StringToBuffer()", () => {
    it("should throw an error if buffer string is not specified", () => {
      try {
        BufferUtil.StringToBuffer(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.MISSING_BUFFER_STRING);
      }
    });

    it("should return a buffer if encoding is not specified", () => {
      const buffer = getTestBuffer();
      const bufferString = BufferUtil.BufferToString(buffer);
      const result = BufferUtil.StringToBuffer(bufferString);
      expect(result).to.be.an.instanceof(Uint8Array);
    });

    it("should return a uint8array", () => {
      const buffer = getTestBuffer();
      const bufferString = BufferUtil.BufferToString(buffer);
      const result = BufferUtil.StringToBuffer(bufferString);
      expect(result instanceof Uint8Array).to.be.true;
    });
  });

  describe("BufferToString() + StringToBuffer()", () => {
    it("should maintain buffer integrity", () => {
      const buffer = getTestBuffer();
      const bufferString = BufferUtil.BufferToString(buffer);
      const result = BufferUtil.StringToBuffer(bufferString);
      expect(result).to.deep.equal(buffer);
    });
  });

  describe("isBufferString()", () => {
    it("should throw an error if buffer string is not specified", () => {
      try {
        BufferUtil.isBufferString(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.MISSING_BUFFER_STRING);
      }
    });
    
    // will always return true for now since utf8 supports all characters
    // ? it("should return false if string is not buffer like")

    it("should return true if string is buffer like", () => {
      const validBufferLikeStrings = [ 
        BufferUtil.BufferToString(getTestBuffer(), "base64"),
        BufferUtil.BufferToString(getTestBuffer(), "utf8")
      ];

      for (const bufferString of validBufferLikeStrings) {
        const result = BufferUtil.isBufferString(bufferString);
        expect(result, `expected buffer-like: ${bufferString}`).to.be.true;
      }
    });
  });

  describe("isBase64String()", () => {
    it("should throw an error if base64 string is not specified", () => {
      try {
        BufferUtil.isBase64String(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.MISSING_TEST_STRING);
      }
    });

    it("should return false if string is not a base64", () => {
      const invalidBase64Strings = [ "~test", "###", "$foo" ];

      for (const invalidBase64String of invalidBase64Strings) {
        const result = BufferUtil.isBase64String(invalidBase64String);
        expect(result).to.be.false;
      }
    });

    it("should return true if string is a valid base64", () => {
      const validBase64Strings = [ "aGVsbG8gd29ybGQ=", "aGVsbG8gd29ybGQ", "aGVsbG8gd29ybGQ==", "aGVsbG8gd29ybGQ=" ];

      for (const validBase64String of validBase64Strings) {
        const result = BufferUtil.isBase64String(validBase64String);
        expect(result).to.be.true;
      }
    });
  });

  describe("isUtf8String()", () => {
    it("should throw an error if utf8 string is not specified", () => {
      try {
        BufferUtil.isUtf8String(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (error) {
        expect((error as Error).message).to.equal(BUFFER_ERROR_MESSAGE.MISSING_TEST_STRING);
      }
    });

    // no such thing as invalid utf8 string: https://www.quora.com/What-is-a-non-UTF-8-character
    // ? it("should return false if string is not a utf8");

    it("should return true if string is a valid utf8", () => {
      const validUtf8Strings = [ "hello", "hello world", "hello world!" ];

      for (const validUtf8String of validUtf8Strings) {
        const result = BufferUtil.isUtf8String(validUtf8String);
        expect(result).to.be.true;
      }
    });
  });
});