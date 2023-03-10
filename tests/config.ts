import { isStringUint8Array } from "../src/utils";

/**
 * Error messages for the unit tests
 */
export const TEST_ERROR = {
  DID_NOT_THROW: "Did not throw an error"
};

/**
 * Provides a reusable function to check if a string is a valid base64 string
 * 
 * @param input - input to check
 */
export function shouldBeStringBuffer(input: string, expect: Chai.ExpectStatic) {
  const result = isStringUint8Array(input);
  expect(result).to.be.true;
}