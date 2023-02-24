/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai"
import { isRawKey, isKey, isSymmetricKey, isAsymmetricKey } from "./key-util"
import { CryptoUtil } from "./crypto-util"
import { Key } from "../interfaces/key-interface"

describe("Key Util Test Suite", () => {
  describe("isRawKey()", () => {
    it("should return true for a valid raw key", async () => {
      const key = await CryptoUtil.generateKey()
      const rawKey = await CryptoUtil.exportKey(key) as Key;
      
      expect(isRawKey(rawKey)).to.be.true;
    })
    
    it("should return false for an invalid raw key", async () => {
      const key = await CryptoUtil.generateKey()
      expect(isRawKey(key)).to.be.false;

      const passKey = await CryptoUtil.generatePassKey({ passphrase: "test" })
      expect(isRawKey(passKey)).to.be.false;

      const privateKey = await CryptoUtil.generatePrivateKey()
      expect(isRawKey(privateKey)).to.be.false;

      const publicKey = await CryptoUtil.generatePublicKey({ privateKey })
      expect(isRawKey(publicKey)).to.be.false;
      
    })
  })

  describe("isKey()", () => {
    it("should return true for a valid key", async () => {
      const key = await CryptoUtil.generateKey()
      expect(isKey(key)).to.be.true;

      const passKey = await CryptoUtil.generatePassKey({ passphrase: "test" })
      expect(isKey(passKey)).to.be.true;

      const privateKey = await CryptoUtil.generatePrivateKey()
      expect(isKey(privateKey)).to.be.true;

      const publicKey = await CryptoUtil.generatePublicKey({ privateKey })
      expect(isKey(publicKey)).to.be.true;

      const extraPrivateKey = await CryptoUtil.generatePrivateKey()
      const sharedKey = await CryptoUtil.generateSharedKey({ privateKey: extraPrivateKey, publicKey })
      expect(isKey(sharedKey)).to.be.true;
    })

    it("should return false for an invalid key", async () => {
      const { crypto } = await CryptoUtil.generateKey();
      expect(isKey(crypto as any)).to.be.false;
    })
  })

  describe("isSymmetricKey()", () => {
    it("should return true for a valid symmetric key", async () => {
      const key = await CryptoUtil.generateKey()
      expect(isSymmetricKey(key)).to.be.true;

      const passKey = await CryptoUtil.generatePassKey({ passphrase: "test" })
      expect(isSymmetricKey(passKey)).to.be.true;

      const privateKey = await CryptoUtil.generatePrivateKey()
      const publicKey = await CryptoUtil.generatePublicKey({ privateKey })
      const otherPrivateKey = await CryptoUtil.generatePrivateKey()
      const sharedKey = await CryptoUtil.generateSharedKey({ privateKey: otherPrivateKey, publicKey })
      expect(isSymmetricKey(sharedKey)).to.be.true;
    })
    
    it("should return false for an invalid symmetric key", async () => {
      const privateKey = await CryptoUtil.generatePrivateKey()
      expect(isSymmetricKey(privateKey)).to.be.false;

      const publicKey = await CryptoUtil.generatePublicKey({ privateKey })
      expect(isSymmetricKey(publicKey)).to.be.false;
    })
  })

  describe("isAsymmetricKey()", () => {
    it("should return true for a valid asymmetric key", async () => {
      const privateKey = await CryptoUtil.generatePrivateKey()
      expect(isAsymmetricKey(privateKey)).to.be.true;

      const publicKey = await CryptoUtil.generatePublicKey({ privateKey })
      expect(isAsymmetricKey(publicKey)).to.be.true;
    })

    it("should return false for an invalid asymmetric key", async () => {
      const key = await CryptoUtil.generateKey()
      expect(isAsymmetricKey(key)).to.be.false;

      const passKey = await CryptoUtil.generatePassKey({ passphrase: "test" })
      expect(isAsymmetricKey(passKey)).to.be.false;

      const privateKey = await CryptoUtil.generatePrivateKey()
      const publicKey = await CryptoUtil.generatePublicKey({ privateKey })
      const otherPrivateKey = await CryptoUtil.generatePrivateKey()
      const sharedKey = await CryptoUtil.generateSharedKey({ privateKey: otherPrivateKey, publicKey })
      expect(isAsymmetricKey(sharedKey)).to.be.false;
    })
  })

})