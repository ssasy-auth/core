/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai"
import { KeyValidator } from "./validator-util"
import { WalletUtil } from "./wallet-util"
import { Key } from "../interfaces/key-interface"

describe("Validator Util Test Suite", () => {
  describe("Key Validator", () => {
    const { isRawKey, isKey, isSymmetricKey, isAsymmetricKey } = KeyValidator

    describe("isRawKey()", () => {
      it("should return true for a valid raw key", async () => {
        const key = await WalletUtil.generateKey()
        const rawKey = await WalletUtil.exportKey(key) as Key;

        expect(isRawKey(rawKey)).to.be.true;
      })

      it("should return false for an invalid raw key", async () => {
        const key = await WalletUtil.generateKey()
        expect(isRawKey(key)).to.be.false;

        const passKey = await WalletUtil.generatePassKey({ passphrase: "test" })
        expect(isRawKey(passKey)).to.be.false;

        const privateKey = await WalletUtil.generatePrivateKey()
        expect(isRawKey(privateKey)).to.be.false;

        const publicKey = await WalletUtil.generatePublicKey({ privateKey })
        expect(isRawKey(publicKey)).to.be.false;

      })
    })

    describe("isKey()", () => {
      it("should return true for a valid key", async () => {
        const key = await WalletUtil.generateKey()
        expect(isKey(key)).to.be.true;

        const passKey = await WalletUtil.generatePassKey({ passphrase: "test" })
        expect(isKey(passKey)).to.be.true;

        const privateKey = await WalletUtil.generatePrivateKey()
        expect(isKey(privateKey)).to.be.true;

        const publicKey = await WalletUtil.generatePublicKey({ privateKey })
        expect(isKey(publicKey)).to.be.true;

        const extraPrivateKey = await WalletUtil.generatePrivateKey()
        const sharedKey = await WalletUtil.generateSharedKey({ privateKey: extraPrivateKey, publicKey })
        expect(isKey(sharedKey)).to.be.true;
      })

      it("should return false for an invalid key", async () => {
        const { crypto } = await WalletUtil.generateKey();
        expect(isKey(crypto as any)).to.be.false;
      })
    })

    describe("isSymmetricKey()", () => {
      it("should return true for a valid symmetric key", async () => {
        const key = await WalletUtil.generateKey()
        expect(isSymmetricKey(key)).to.be.true;

        const passKey = await WalletUtil.generatePassKey({ passphrase: "test" })
        expect(isSymmetricKey(passKey)).to.be.true;

        const privateKey = await WalletUtil.generatePrivateKey()
        const publicKey = await WalletUtil.generatePublicKey({ privateKey })
        const otherPrivateKey = await WalletUtil.generatePrivateKey()
        const sharedKey = await WalletUtil.generateSharedKey({ privateKey: otherPrivateKey, publicKey })
        expect(isSymmetricKey(sharedKey)).to.be.true;
      })

      it("should return false for an invalid symmetric key", async () => {
        const privateKey = await WalletUtil.generatePrivateKey()
        expect(isSymmetricKey(privateKey)).to.be.false;

        const publicKey = await WalletUtil.generatePublicKey({ privateKey })
        expect(isSymmetricKey(publicKey)).to.be.false;
      })
    })

    describe("isAsymmetricKey()", () => {
      it("should return true for a valid asymmetric key", async () => {
        const privateKey = await WalletUtil.generatePrivateKey()
        expect(isAsymmetricKey(privateKey)).to.be.true;

        const publicKey = await WalletUtil.generatePublicKey({ privateKey })
        expect(isAsymmetricKey(publicKey)).to.be.true;
      })

      it("should return false for an invalid asymmetric key", async () => {
        const key = await WalletUtil.generateKey()
        expect(isAsymmetricKey(key)).to.be.false;

        const passKey = await WalletUtil.generatePassKey({ passphrase: "test" })
        expect(isAsymmetricKey(passKey)).to.be.false;

        const privateKey = await WalletUtil.generatePrivateKey()
        const publicKey = await WalletUtil.generatePublicKey({ privateKey })
        const otherPrivateKey = await WalletUtil.generatePrivateKey()
        const sharedKey = await WalletUtil.generateSharedKey({ privateKey: otherPrivateKey, publicKey })
        expect(isAsymmetricKey(sharedKey)).to.be.false;
      })
    })
  })
})