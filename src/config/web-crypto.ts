import { webcrypto } from "crypto";

let WebCrypto: Crypto;
let CryptoKey: CryptoKey;

if (typeof window !== "undefined" && window.crypto) {
  WebCrypto = window.crypto;
} else {
  // Cast to `any` to avoid TypeScript errors since `webcrypto` is not available in Node.js by default
  WebCrypto = webcrypto as unknown as Crypto;
}

export { WebCrypto, CryptoKey };
