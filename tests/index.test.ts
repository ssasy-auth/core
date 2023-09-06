import { expect } from "chai";
import { Wallet } from "../src/wallet";
import { SerializerModule, SerializerChecker } from "../src/modules";
import type { ChallengeResult } from "../src/wallet";
import type { RawKey, AdvancedCiphertext } from "../src/interfaces";

describe("[End-to-End Test Suite]", () => {

  describe("Claimant and verifier engage in a challenge response ritual", () => {
    const VERIFIER_PRIVATE_KEY = {
      type: "private-key",
      crypto: {
        key_ops: [
          "deriveKey"
        ],
        ext: true,
        kty: "EC",
        x: "TuVgJkd6D3-0S3pLUnxWM9-nYN1wlMCFeNtc3FpFEzw",
        y: "vxb6ahvjqG1qvaFqYl8wLJYvFtbj0P1RZxBiuJ2H7VA",
        crv: "P-256",
        d: "Qa_bQVL9-qF921Ptm0ujs1Hnadn43pC49GPfSIOqMGE"
      }
    };

    const CLAIMANT_PRIVATE_KEY = {
      type: "private-key",
      crypto: {
        key_ops: [
          "deriveKey"
        ],
        ext: true,
        kty: "EC",
        x: "HQHnwQKj1er9yRKAwBQxnyhl0nGFBaZoClu72rbmVb0",
        y: "3oagkoeGui9OuCb6G8DcPwacY0ChK950NT-kPp7qwDY",
        crv: "P-256",
        d: "iENPCJpw11w1sJykgQzw8B_4vsETAdp6eyjuaga1OW0"
      }
    };

    let verifier: Wallet;
    let claimant: Wallet;

    beforeEach(async () => {
      const verifierKeyUri: string = await SerializerModule.serializeKey(VERIFIER_PRIVATE_KEY as RawKey);
      const claimantKeyUri: string = await SerializerModule.serializeKey(CLAIMANT_PRIVATE_KEY as RawKey);

      verifier = new Wallet(verifierKeyUri);
      claimant = new Wallet(claimantKeyUri);
    });

    let encryptedChallengeUri: string;

    it("verifier should create an encrypted challenge using claimant's public key uri", async () => {
      const claimantPublicKeyUri: string = await claimant.getPublicKey();
      encryptedChallengeUri = await verifier.generateChallenge(claimantPublicKeyUri);

      expect(encryptedChallengeUri).to.be.a("string");
      expect(SerializerChecker.isCiphertextUri(encryptedChallengeUri)).to.be.true;
    });

    let encryptedChallengeResponseUri: string;

    it("claimant should create an encrypted challenge response using verifier's public key uri", async () => {
      encryptedChallengeResponseUri = await claimant.generateChallengeResponse(encryptedChallengeUri);

      expect(encryptedChallengeResponseUri).to.be.a("string");
      expect(SerializerChecker.isCiphertextUri(encryptedChallengeResponseUri)).to.be.true;
    });

    it("claimant should add a signature to the challenge response", async () => {
      const encryptedChallengeResponse: AdvancedCiphertext = await SerializerModule.deserializeCiphertext(encryptedChallengeResponseUri);

      expect(encryptedChallengeResponse).to.be.an("object");
      expect(encryptedChallengeResponse).to.have.property("signature")
    });

    it("verifier should succesfully verify the challenge response", async () => {
      const result: ChallengeResult | null = await verifier.verifyChallengeResponse(encryptedChallengeResponseUri);

      expect(result).to.be.an("object");
      expect(result).to.have.property("publicKey").that.is.string;
      expect(result).to.have.property("signature").that.is.string;

      expect(SerializerChecker.isKeyUri(result?.publicKey as string)).to.be.true;
      expect(SerializerChecker.isSignatureUri(result?.signature as string)).to.be.true;
    });
  });

  describe("Challenge response ritual using legacy URIs", () => {
    
    const VERIFIER_PRIVATE_KEY = {
      type: "private-key",
      crypto: {
        key_ops: [
          "deriveKey"
        ],
        ext: true,
        kty: "EC",
        x: "TuVgJkd6D3-0S3pLUnxWM9-nYN1wlMCFeNtc3FpFEzw",
        y: "vxb6ahvjqG1qvaFqYl8wLJYvFtbj0P1RZxBiuJ2H7VA",
        crv: "P-256",
        d: "Qa_bQVL9-qF921Ptm0ujs1Hnadn43pC49GPfSIOqMGE"
      }
    };

    const CLAIMANT_PRIVATE_KEY = {
      "type": "private-key",
      "crypto": {
        "crv": "P-256",
        "d": "Udw4rlpbJX2N5qtiBNtwYnd7Me0ek1BKASEDLQr5UUM",
        "ext": true,
        "key_ops": [
          "deriveKey"
        ],
        "kty": "EC",
        "x": "d9oZ6UPqNeRu3Goq8LC3BjoC2zYcStWoakMDvYEwVn0",
        "y": "AFC-mBqsXFcTFl3vMs4L_tTc03j-_OBfefh_deJlJi4"
      }
    };

    const CLAIMANT_SIGNATURE = "ssasy://signature?data=t4yCYCwlpGf7%2BRq7X6iDflG%2Fj%2B1zyPI7wcDWwF9rzUZAD2kKdV1cxKlFdPYuVOyG%2FvDa21R0D94xVnQEt0RT4%2B9ojNQRtrNS7VH8sB0J6zX0mdmIyq6aDyhX85RkcoD4UfEUAgUONNPoQZ3yAr58uMG9qyW2Nw5Vha7Mz7JcFRSa2THQcXTsuDvZZQslwJDV8iWph%2F3Fji%2Fq8m79OoGpffFqIUI86%2FZ8AF1n65BMU8ecgm2glFLIImOANFQsWkTLiviOv5vT1AIw0jL3ZI6RGcvuehoJGyHbo3528VG783uzFAmY3iQX%2FUtPcPTsoPar%2F%2FTxhD0kzgBboUYZcZjUPtdvQvMgO2cCg2U%2FZOokqNWqwLM0ex5Ek9xl2mfCsk3De9ZFLqvy61jgEtqOEQGo581TOGlzWZ6ODp8fPgUL6a3N7lhzP4yL9l%2B0jFtfNAlI6jQ98cBraIP0eJkVbO81HQR%2Bmagnve%2FDNA0NXYNsS3uu69jzDvq9WpOwOZvGOxeTSCOfYRxB22Mc%2FoifX5xIGe9LPUzCmAHGDbVfA8OQiPExwUn%2BQ9xyYsLGiVLdnfJpcdPzZCSE9oik5QNmDY0PMfZGGV1SnKZS1mXMAqx9dlRZknpRePAfQsvhiLxToXoiRzn7UG8y0yE56W0Vql7TJBt%2BUt1v25CNNramdgzQlw%3D%3D&iv=JGalPbjLX1VYiRcYZwaBqw%3D%3D";

    let verifier: Wallet;
    let claimant: Wallet;

    beforeEach(async () => {
      const verifierKeyUri: string = await SerializerModule.serializeKey(VERIFIER_PRIVATE_KEY as RawKey);
      const claimantKeyUri: string = await SerializerModule.serializeKey(CLAIMANT_PRIVATE_KEY as RawKey);

      verifier = new Wallet(verifierKeyUri);
      claimant = new Wallet(claimantKeyUri);
    });

    let encryptedChallengeUri: string;

    it("verifier should create an encrypted challenge using claimant's public key uri and the saved user signature", async () => {
      const claimantPublicKeyUri: string = await claimant.getPublicKey();
      encryptedChallengeUri = await verifier.generateChallenge(claimantPublicKeyUri, CLAIMANT_SIGNATURE);

      expect(encryptedChallengeUri).to.be.a("string");
      expect(SerializerChecker.isCiphertextUri(encryptedChallengeUri)).to.be.true;
    });

    let encryptedChallengeResponseUri: string;

    it("claimant should create an encrypted challenge response using verifier's public key uri", async () => {
      encryptedChallengeResponseUri = await claimant.generateChallengeResponse(encryptedChallengeUri);

      expect(encryptedChallengeResponseUri).to.be.a("string");
      expect(SerializerChecker.isCiphertextUri(encryptedChallengeResponseUri)).to.be.true;
    });

    it("claimant should add a signature to the challenge response", async () => {
      const encryptedChallengeResponse: AdvancedCiphertext = await SerializerModule.deserializeCiphertext(encryptedChallengeResponseUri);

      expect(encryptedChallengeResponse).to.be.an("object");
      expect(encryptedChallengeResponse).to.have.property("signature")
    });

    it("verifier should succesfully verify the challenge response", async () => {
      const result: ChallengeResult | null = await verifier.verifyChallengeResponse(encryptedChallengeResponseUri);

      expect(result).to.be.an("object");
      expect(result).to.have.property("publicKey").that.is.string;
      expect(result).to.have.property("signature").that.is.string;

      expect(SerializerChecker.isKeyUri(result?.publicKey as string)).to.be.true;
      expect(SerializerChecker.isSignatureUri(result?.signature as string)).to.be.true;
    });
  });
});
