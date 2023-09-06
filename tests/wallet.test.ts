/* eslint-disable @typescript-eslint/no-explicit-any */
import { expect } from "chai";
import { TEST_ERROR } from "./config";
import { BufferUtil } from "../src/utils";
import {
  KeyModule,
  KeyChecker,
  CryptoModule,
  SerializerModule,
  ChallengeModule,
  CryptoChecker,
  SerializerChecker
} from "../src/modules";
import { Wallet, WALLET_ERROR_MESSAGE } from "../src/wallet";
import {
  KeyType,
  type AdvancedCiphertext,
  type Challenge,
  type PrivateKey,
  type PublicKey,
  type StandardCiphertext,
  type RawKey,
  type SecureContextKey
} from "../src/interfaces";

describe("[Wallet Class Test Suite]", () => {
  const testPassPhrase = "passphrase";
  
  let testWallet: Wallet;
  let testPrivateKey: PrivateKey;
  let testPublicKey: PublicKey;
  let testPrivateKeyUri: string;
  let testPublicKeyUri: string;
  
  let friendPrivateKey: PrivateKey;
  let friendPublicKey: PublicKey;
  let friendPrivateKeyUri: string;
  let friendPublicKeyUri: string;
  
  let thirdPartyPrivateKey: PrivateKey;
  let thirdPartyPrivateKeyUri: string;

  before(async () => {
    testPrivateKey = await KeyModule.generatePrivateKey();
    testPublicKey = await KeyModule.generatePublicKey({ privateKey: testPrivateKey });
    testPrivateKeyUri = await SerializerModule.serializeKey(testPrivateKey);
    testWallet = new Wallet(testPrivateKeyUri);
    testPublicKeyUri = await SerializerModule.serializeKey(testPublicKey);

    friendPrivateKey = await KeyModule.generatePrivateKey();
    friendPublicKey = await KeyModule.generatePublicKey({ privateKey: friendPrivateKey });
    friendPrivateKeyUri = await SerializerModule.serializeKey(friendPrivateKey);
    friendPublicKeyUri = await SerializerModule.serializeKey(friendPublicKey);

    thirdPartyPrivateKey = await KeyModule.generatePrivateKey();
    thirdPartyPrivateKeyUri = await SerializerModule.serializeKey(thirdPartyPrivateKey);
  })

  describe("constructor()", () => {
    it("should throw an error if private key uri (string) is not provided", async () => {
      const invalidArguments = [
        // must be a valid key uri
        "invalid",
        
        // must be a private key uri
        testPublicKeyUri,

        // must a uri (string)
        await testWallet.getPublicKey(),

        // must be a key uri (string)
        testPrivateKey 
      ];

      for (const invalidArgument of invalidArguments) {

        try {
          new Wallet(invalidArgument as any);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message, `should throw for argument ${invalidArgument}`).to.equal(WALLET_ERROR_MESSAGE.INVALID_KEY);
        }
      }
    })
    
    it("should throw an error if key is not provided", async () => {
      try {
        new Wallet(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CONSTRUCTOR_PARAMS);
      }
    })

    it("should return a wallet instance if valid private key uri is provided", async () => {
      const wallet = new Wallet(testPrivateKeyUri);
      expect(wallet).to.be.instanceOf(Wallet);
    })
  })

  describe("getPublicKey()", () => {
    let wallet: Wallet;

    beforeEach(async () => {
      wallet = new Wallet(testPrivateKeyUri);
    })

    it("should return a public key uri", async () => {
      const publicKey: string = await wallet.getPublicKey();

      expect(publicKey).to.be.a("string");
      expect(publicKey.startsWith(SerializerModule.PREFIX.URI.KEY)).to.be.true;
      expect(SerializerChecker.isKeyUri(publicKey, { type: KeyType.PublicKey })).to.be.true;
    })

    it("should return raw key, if raw flag is set", async () => {
      const rawPublicKey: RawKey = await wallet.getPublicKey({ raw: true });

      expect(rawPublicKey).to.be.a("object");
      expect(KeyChecker.isRawKey(rawPublicKey)).to.be.true;
    })

    it("should return secure context key, if secure flag is set", async () => {
      const securePublicKey: SecureContextKey = await wallet.getPublicKey({ secure: true });

      expect(securePublicKey).to.be.a("object");
      expect(KeyChecker.isAsymmetricKey(securePublicKey)).to.be.true;
    })

    it("should return correct public key (uri by default)", async () => {
      const publicKeyUri: string = await wallet.getPublicKey();
      expect(publicKeyUri).to.deep.equal(testPublicKeyUri);
    })
  })

  describe("encrypt()", () => {
    let wallet: Wallet;

    beforeEach(async () => {
      wallet = new Wallet(testPrivateKeyUri);
    })

    it("should throw an error if key is not supported", async () => {
      const unsportedKeys = [
        // must be a public key
        testPrivateKeyUri,

        // must be a key uri (string)
        await KeyModule.generateKey()
      ];

      for (const unsupportedKey of unsportedKeys) {
        try {
          await wallet.encrypt(unsupportedKey as any, "data");
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_KEY)
        }
      }
    })

    it("should throw an error if data is not provided", async () => {
      try {
        await wallet.encrypt(friendPublicKeyUri, undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_PAYLOAD);
      }
    })

    it("should return a ciphertext uri", async () => {
      const payload = "data"; 
      const ciphertextUri = await wallet.encrypt(friendPublicKeyUri, payload);

      expect(ciphertextUri).to.be.a("string");
    })

    it("should be possible to decode ciphertext uri", async () => {
      const payload = "data";
      const ciphertextUri = await wallet.encrypt(friendPublicKeyUri, payload);

      const ciphertext = await SerializerModule.deserializeCiphertext(ciphertextUri);
      expect(ciphertext.data).to.not.equal(payload);
      expect(ciphertext.data).to.not.include(payload);
      // iv should be a valid Uint8Array uri
      const result = BufferUtil.isBufferString(ciphertext.iv);
      expect(result).to.be.true;
    })

    it("should return an ciphertext uri with salt param if key is a passphrase", async () => {
      const payload = "data";
      const ciphertextUri = await wallet.encrypt(testPassPhrase, payload);
      const ciphertext: AdvancedCiphertext = await SerializerModule.deserializeCiphertext(ciphertextUri) as AdvancedCiphertext;

      expect(ciphertext.salt).to.exist;
    })

    it("should return an advanced ciphertext with sender and recipient public key, if public key is passed", async () => {
      const payload = "data";
      const ciphertextUri = await wallet.encrypt(friendPublicKeyUri, payload);
      const ciphertext: AdvancedCiphertext = await SerializerModule.deserializeCiphertext(ciphertextUri) as AdvancedCiphertext;
      
      expect(ciphertext.sender).to.exist;
      expect(ciphertext.sender).to.deep.equal(testPublicKey); // wallet public key

      expect(ciphertext.recipient).to.exist;
      expect(ciphertext.recipient).to.deep.equal(friendPublicKey);
    })

    it("should return an advanced ciphertext if serialized public key (key uri) is passed", async () => {
      const friendPrivateKey = await KeyModule.generatePrivateKey();
      const friendPublicKey = await KeyModule.generatePublicKey({
        privateKey: friendPrivateKey
      });
      
      const serializedPublicKey = await SerializerModule.serializeKey(friendPublicKey);
      const payload = "data";

      const ciphertextUri = await wallet.encrypt(serializedPublicKey, payload);
      expect(ciphertextUri.startsWith(SerializerModule.PREFIX.URI.CIPHERTEXT)).to.be.true;

      // expect ciphertext recipient to be the serialized public key belonging to the friend
      const ciphertext: AdvancedCiphertext = await SerializerModule.deserializeCiphertext(ciphertextUri) as AdvancedCiphertext;
      expect(ciphertext.recipient).to.deep.equal(friendPublicKey);
    })
  })

  describe("decrypt()", () => {
    let wallet: Wallet;
    let friendWallet: Wallet;
    let encryptedMessageFromFriend: string;
    

    beforeEach(async () => {
      wallet = new Wallet(testPrivateKeyUri);
      friendWallet = new Wallet(friendPrivateKeyUri);
      encryptedMessageFromFriend = await friendWallet.encrypt(testPublicKeyUri, "data");
    })

    it("should throw an error if key is not supported", async () => {

      const unsupportedKeys = [
        // must be a public key
        testPrivateKeyUri,

        // must be a key uri (string)
        await KeyModule.generateKey()
      ];

      for (const unsupportedKey of unsupportedKeys) {
        try {
          await wallet.decrypt(unsupportedKey as any, encryptedMessageFromFriend);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error = e as Error;
          expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_KEY);
        }
      }
    })
    
    it("should throw an error if ciphertext is not provided", async () => {
      try {
        await wallet.decrypt(testPassPhrase, undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
      }
    })

    it("should return decrypted data that was encrypted with public key uri", async () => {
      const payload = "data";
      const decrypted = await wallet.decrypt(friendPublicKeyUri, encryptedMessageFromFriend);
      expect(decrypted).to.equal(payload);
    })
  })

  describe("generateSignature()", () => {
    let wallet: Wallet;

    beforeEach(async () => {
      wallet = new Wallet(testPrivateKeyUri);
    })

    it("should return a signature uri", async () => {
      const payload = "data";
      const encryptedSignatureString = await wallet.generateSignature(payload);
      expect(encryptedSignatureString).to.be.an("string");

      const encryptedSignature = await SerializerModule.deserializeSignature(encryptedSignatureString);
      const isCiphertext = CryptoChecker.isCiphertext(encryptedSignature);
      expect(isCiphertext).to.be.true;
    });

    it("should create signature based on wallet private key", async () => {
      const payload = "data";
      const encryptedSignatureString = await wallet.generateSignature(payload);
      
      // verify with wallet function
      const isValidInWallet = await wallet.verifySignature(encryptedSignatureString);
      expect(isValidInWallet).to.not.be.null;
      
      // verify with CryptoModule
      const encryptedSignature = await SerializerModule.deserializeSignature(encryptedSignatureString);
      const isValid = await CryptoModule.verify(testPrivateKey, encryptedSignature);
      expect(isValid).to.not.be.null;
    });
  });

  describe("verifySignature()", () => {
    it("should return challenge string, if signature is valid", async () => {
      const wallet = new Wallet(testPrivateKeyUri);
      const payload = "data";
      const encryptedSignatureString: string = await wallet.generateSignature(payload);
      const result: string | null = await wallet.verifySignature(encryptedSignatureString);
      expect(result).to.be.a.string;
    });

    it("should return null if signature is invalid", async () => {
      const friendWallet = new Wallet(friendPrivateKeyUri);
      const payload = "data";
      const encryptedSignatureString: string = await friendWallet.generateSignature(payload);
      
      const wallet = new Wallet(testPrivateKeyUri);
      const isValid = await wallet.verifySignature(encryptedSignatureString);
      expect(isValid).to.be.null;
    });
  });

  describe("generateChallenge()", () => {
    let wallet: Wallet;

    beforeEach(async () => {
      wallet = new Wallet(testPrivateKeyUri);
    })

    it("should return string", async () => {
      const encryptedChallengeString = await wallet.generateChallenge(friendPublicKeyUri);
      expect(encryptedChallengeString).to.be.an("string");
    });

    it("should return challenge URI with data, iv, sender and recipient", async () => {
      const encryptedChallengeString = await wallet.generateChallenge(friendPublicKeyUri);
      const ciphertext = await SerializerModule.deserializeCiphertext(encryptedChallengeString) as AdvancedCiphertext;
      
      expect(ciphertext.data).to.exist;
      expect(ciphertext.iv).to.exist;
      expect(ciphertext.sender).to.exist;
      expect(ciphertext.recipient).to.exist;
    });

    it("should accept a string as public key", async () => {
      const serializedKey = await SerializerModule.serializeKey(friendPublicKey);
      
      let errorThrown = false;

      try {
        const encryptedChallengeString = await wallet.generateChallenge(serializedKey);
        const encryptedChallenge = await SerializerModule.deserializeCiphertext(encryptedChallengeString) as AdvancedCiphertext;

        expect(encryptedChallenge).to.exist;
        expect(encryptedChallenge.recipient).to.deep.equal(friendPublicKey);
        expect(encryptedChallenge.sender).to.deep.equal(testPublicKey);
        expect(encryptedChallenge.data).to.exist;
        expect(encryptedChallenge.iv).to.exist;
      } catch (error) {
        errorThrown = true;
      }
      
      expect(errorThrown).to.be.false;
      
      
    });

    it("should return challenge URI with signature if it is provided", async () => {
      const friendWallet: Wallet = new Wallet(friendPrivateKeyUri);
      
      // create a challenge so that friend can solve it
      const encryptedChallengeString: string = await wallet.generateChallenge(friendPublicKeyUri);

      // friend solves the challenge and adds their signature
      const encryptedSolutionString: string = await friendWallet.generateChallengeResponse(encryptedChallengeString);

      // decode solution
      const encryptedSolution: AdvancedCiphertext = await SerializerModule.deserializeCiphertext(encryptedSolutionString);

      // decode signature in solution
      const signatureString: string = await SerializerModule.serializeSignature(encryptedSolution.signature as StandardCiphertext);

      // function under test
      const mainEncryptedChallengeString: string = await wallet.generateChallenge(friendPublicKeyUri, signatureString);

      // decode new challenge
      const mainEncryptedChallenge: AdvancedCiphertext = await SerializerModule.deserializeCiphertext(mainEncryptedChallengeString);

      expect(mainEncryptedChallenge.signature).to.exist;
      expect(mainEncryptedChallenge.signature?.data).to.deep.equal(encryptedSolution.signature?.data);
      expect(mainEncryptedChallenge.signature?.iv).to.deep.equal(encryptedSolution.signature?.iv);
    })

    it("should set encrypted challenge sender to the wallet public key and recipient to the provided public key", async () => {
      const ciphertext = await wallet.generateChallenge(friendPublicKeyUri);
      const deserializedCiphertext: AdvancedCiphertext = await SerializerModule.deserializeCiphertext(ciphertext);
      
      expect(deserializedCiphertext.sender).to.deep.equal(testPublicKey); // wallet public key
      expect(deserializedCiphertext.recipient).to.deep.equal(friendPublicKey);
    });
  })

  describe("generateChallengeResponse()", () => {
    let wallet: Wallet;
    let challenge: Challenge; // generated by friend wallet
    let encryptedChallenge: AdvancedCiphertext; // generated by friend wallet
    let encryptedChallengeString: string;

    beforeEach(async () => {
      wallet = new Wallet(testPrivateKeyUri);
      
      // set challenge
      challenge = await ChallengeModule.generateChallenge(friendPrivateKey, testPublicKey);

      // encode challenge
      const challengeString = await SerializerModule.serializeChallenge(challenge);

      // derive shared key
      const sharedKey = await KeyModule.generateSharedKey({
        privateKey: friendPrivateKey, publicKey: testPublicKey
      });
      
      // encrypt challenge
      encryptedChallenge = await CryptoModule.encrypt(sharedKey, challengeString, friendPublicKey, testPublicKey);

      // convert encrypted challenge to string
      encryptedChallengeString = await SerializerModule.serializeCiphertext(encryptedChallenge);
    })

    it("should throw an error if the ciphertext is not provided", async () => {
      try {
        await wallet.generateChallengeResponse(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
      }
    })

    it("should throw an error if the sender or recipient is not provided in ciphertext", async () => {
      const mockCiphertext: AdvancedCiphertext = {
        ...encryptedChallenge,
        sender: undefined as any, // <-- should be friend public key
        recipient: undefined as any // <-- should be wallet public key
      }

      const mockCiphertextString: string = await SerializerModule.serializeCiphertext(mockCiphertext);
      
      try {
        await wallet.generateChallengeResponse(mockCiphertextString);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_PARTIES);
      }
    })

    it("should throw an error if the ciphertext recipient does not match the wallet public key", async () => {
      const mockCiphertext: AdvancedCiphertext = {
        ...encryptedChallenge,
        recipient: friendPublicKey // <-- should be wallet public key
      }

      const mockCiphertextString: string = await SerializerModule.serializeCiphertext(mockCiphertext);
      
      try {
        await wallet.generateChallengeResponse(mockCiphertextString);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
      }
    })
    
    it("should throw an error if invalid challenge is provided", async () => {
      const mockCiphertext: AdvancedCiphertext = {
        ...encryptedChallenge,
        data: "invalid" // <-- should be challenge
      }

      const mockCiphertextString: string = await SerializerModule.serializeCiphertext(mockCiphertext);

      try {
        await wallet.generateChallengeResponse(mockCiphertextString);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
      }
    })

    it("should return a encrypted challenge-response as string", async () => {
      const encryptedChallengeResponseString = await wallet.generateChallengeResponse(encryptedChallengeString);
      const encryptedChallengeResponse = await SerializerModule.deserializeCiphertext(encryptedChallengeResponseString);

      expect(encryptedChallengeResponse.data).to.exist;
      expect(encryptedChallengeResponse.iv).to.exist;
    })

    it("should return a encrypted challenge-response with a signature", async () => {
      const encryptedChallengeResponseString = await wallet.generateChallengeResponse(encryptedChallengeString);
      const encryptedChallengeResponse = await SerializerModule.deserializeCiphertext(encryptedChallengeResponseString) as AdvancedCiphertext;

      expect(encryptedChallengeResponse.signature).to.exist;
      const isValidCiphertext = CryptoChecker.isCiphertext(encryptedChallengeResponse);
      expect(isValidCiphertext).to.be.true;
    });

    it("should return a signature that matches the solved challenger", async () => {
      const encryptedChallengeResponseString = await wallet.generateChallengeResponse(encryptedChallengeString);
      const encryptedChallengeResponse = await SerializerModule.deserializeCiphertext(encryptedChallengeResponseString) as AdvancedCiphertext;
      
      // extract solution from ciphertext
      const sharedKey = await KeyModule.generateSharedKey({
        privateKey: testPrivateKey, publicKey: encryptedChallenge.sender as PublicKey 
      });
      const decryptedChallengeResponse = await CryptoModule.decrypt(sharedKey, encryptedChallengeResponse)
      const challengeResponse = await SerializerModule.deserializeChallenge(decryptedChallengeResponse);
      
      // extract signature from ciphertext
      const signature = encryptedChallengeResponse.signature as StandardCiphertext;

      // encode signature
      const signatureString = await SerializerModule.serializeSignature(signature);
      
      const serializedChallengeSolution = await wallet.verifySignature(signatureString);
      expect(serializedChallengeSolution).to.be.a.string;

      const challengeSolution: Challenge = await SerializerModule.deserializeChallenge(serializedChallengeSolution as string);
      expect(challengeSolution).to.deep.equal(challengeResponse);
    });

    it("should return a signature that is verifiable by the wallet", async () => {
      const encryptedChallengeResponseString = await wallet.generateChallengeResponse(encryptedChallengeString);
      const encryptedChallengeResponse = await SerializerModule.deserializeCiphertext(encryptedChallengeResponseString) as AdvancedCiphertext;
      
      // extract signature from ciphertext
      const signature = encryptedChallengeResponse.signature as StandardCiphertext;

      // encode signature
      const signatureString = await SerializerModule.serializeSignature(signature);

      const isValidSignature = await wallet.verifySignature(signatureString)
      expect(isValidSignature).to.not.be.null;
    });

    it("should set encrypted challenge-response sender to the claimant's public key and recipient to the verifier's public key", async () => {
      const encryptedChallengeResponseString = await wallet.generateChallengeResponse(encryptedChallengeString);
      const encryptedChallengeResponse = await SerializerModule.deserializeCiphertext(encryptedChallengeResponseString) as AdvancedCiphertext;

      expect(encryptedChallengeResponse.sender).to.deep.equal(challenge.claimant);
      expect(encryptedChallengeResponse.recipient).to.deep.equal(challenge.verifier);
    })
  })

  describe("generateChallengeResponse() with required signature", () => {
    let wallet: Wallet;
    let encryptedChallenge: AdvancedCiphertext; // generated by friend wallet
    let encryptedChallengeString: string;

    beforeEach(async () => {
      wallet = new Wallet(testPrivateKeyUri);
      const friendWallet: Wallet = new Wallet(friendPrivateKeyUri);

      encryptedChallengeString = await friendWallet.generateChallenge(await wallet.getPublicKey());
      encryptedChallenge = await SerializerModule.deserializeCiphertext(encryptedChallengeString);
    })

    it("should throw an error if ciphertext does not contain a signature", async () => {
      try {
        await wallet.generateChallengeResponse(
          encryptedChallengeString,
          { requireSignature: true }
        );

        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (err) {
        const error = err as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_SIGNATURE);
      }
    })
    
    it("should throw an error if challenge signature is invalid", async () => {
      const invalidSignatures = [
        "invalid",
        null as any,
        undefined as any
      ];

      for (const invalidString of invalidSignatures) {
        let encryptedChallengeUri = await SerializerModule.serializeCiphertext(encryptedChallenge);

        // inject invalid signature
        encryptedChallengeUri += `&signature=${invalidString}`
        
        try {
          await wallet.generateChallengeResponse(
            encryptedChallengeUri, 
            { requireSignature: true }
          );
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (error) {
          expect((error as Error).message).to.be.oneOf([
            WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_SIGNATURE,
            WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE,
            WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT
          ]);
        }
      }
    })

    it("should throw an error if challenge signature does not match parties", async () => {
      /**
       * scenario:
       * 
       * 1. friend wallet generates challenge
       * 2. you solve the challenge and attach your signature
       * 3. third-party wallet
       *    - captures the signature
       *    - tries to replay it with a different public key (not the friend's)
       */

      // step 1. friend wallet generates challenge
      const friendWallet: Wallet = new Wallet(friendPrivateKeyUri);
      const encryptedFriendChallengeString: string = await friendWallet.generateChallenge(testPublicKeyUri);

      // step 2. you solve the challenge and attach your signature
      const encryptedChallengeResponseString: string = await wallet.generateChallengeResponse(encryptedFriendChallengeString);
      const encryptedChallengeResponse: AdvancedCiphertext = await SerializerModule.deserializeCiphertext(encryptedChallengeResponseString);

      // step 3. third-party wallet captures the signature and tries to replay it with a different public key (not the friend's)
      const thirdPartyWallet: Wallet = new Wallet(thirdPartyPrivateKeyUri);
      const encryptedThirdPartyChallengeString: string = await thirdPartyWallet.generateChallenge(testPublicKeyUri);
  
      // ... third party injects your signature into their challenge
      const encryptedThirdPartyChallengeWithReplay: AdvancedCiphertext = {
        ...await SerializerModule.deserializeCiphertext(encryptedThirdPartyChallengeString),
        signature: encryptedChallengeResponse.signature
      }

      // ... third party encodes challenge
      const encryptedThirdPartyChallengeWithReplayString: string = await SerializerModule.serializeCiphertext(encryptedThirdPartyChallengeWithReplay);

      try {
        await wallet.generateChallengeResponse(encryptedThirdPartyChallengeWithReplayString, {
          requireSignature: true 
        });
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (err) {
        const error = err as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_SIGNATURE_ORIGIN);
      }

    });

    it("should return challenge response if valid signature is provided", async () => {
      const friendWallet: Wallet = new Wallet(friendPrivateKeyUri);
      const encryptedChallengeUriFromFriend: string = await friendWallet.generateChallenge(testPublicKeyUri);

      // produce solution with signature
      const encryptedChallengeResponseUri: string = await wallet.generateChallengeResponse(encryptedChallengeUriFromFriend);

      // ... friend saves signature
      const response = await friendWallet.verifyChallengeResponse(encryptedChallengeResponseUri)

      // friend generates a new challenge with signature
      const newEncryptedFriendChallengeString: string = await friendWallet.generateChallenge(testPublicKeyUri, response?.signature);

      // ... friend sends challenge to wallet

      // wallet solves challenge with signature
      const walletSolutionWithSignature = await wallet.generateChallengeResponse(newEncryptedFriendChallengeString, { requireSignature: true });

      expect(walletSolutionWithSignature).to.not.be.null;
    });
  })

  describe("verifyChallengeResponse()", () => {
    let wallet: Wallet; // <- verifier
    let friendWallet: Wallet; // <- claimant
    
    let encryptedChallenge: AdvancedCiphertext; // generated by verifier
    let encryptedChallengeResponse: AdvancedCiphertext; // generated by claimant
    let encryptedChallengeResponseString: string; // generated by verifier

    beforeEach(async () => {
      wallet = new Wallet(testPrivateKeyUri);
      friendWallet = new Wallet(friendPrivateKeyUri);
      
      const encryptedChallengeString = await wallet.generateChallenge(await friendWallet.getPublicKey())
      encryptedChallenge = await SerializerModule.deserializeCiphertext(encryptedChallengeString);
      
      encryptedChallengeResponseString = await friendWallet.generateChallengeResponse(encryptedChallengeString)
      encryptedChallengeResponse = await SerializerModule.deserializeCiphertext(encryptedChallengeResponseString);
    })

    it("should throw an error if the ciphertext is not provided", async () => {
      try {
        await wallet.verifyChallengeResponse(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
      }
    })

    it("should throw an error if the sender or recipient is not provided in ciphertext", async () => {
      const mockSolutionCiphertext: AdvancedCiphertext = {
        ...encryptedChallengeResponse,
        sender: undefined as any, // <-- should be wallet public key
        recipient: undefined as any // <-- should be friend public key
      }

      const mockSolutionCiphertextString: string = await SerializerModule.serializeCiphertext(mockSolutionCiphertext);

      try {
        await wallet.verifyChallengeResponse(mockSolutionCiphertextString);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_PARTIES);
      }
    })

    it("should throw an error if the ciphertext recipient does not match the wallet public key", async () => {
      const thirdPartyWallet = new Wallet(thirdPartyPrivateKeyUri);
      const notYourEncryptedChallengeString = await friendWallet.generateChallenge(await thirdPartyWallet.getPublicKey()); // friend generates challenge for third party
      const notYourEncryptedChallengeResponseString = await thirdPartyWallet.generateChallengeResponse(notYourEncryptedChallengeString); // third party solves challenge

      try {
        await wallet.verifyChallengeResponse(notYourEncryptedChallengeResponseString);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
      }
    })

    it("should throw an error if the challenge is not provided", async () => {
      try {
        await wallet.verifyChallengeResponse(undefined as any);
        expect.fail(TEST_ERROR.DID_NOT_THROW);
      } catch (e) {
        const error = e as Error;
        expect(error.message).to.equal(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
      }
    })

    it("should return object with claimant's public key if the challenge has been solved", async () => {
      const result = await wallet.verifyChallengeResponse(encryptedChallengeResponseString);
      expect(result).to.be.an("object");
      expect(result).to.have.property("publicKey");
      
      // key should be a string
      expect(result?.publicKey).to.be.a.string;

      // decode key
      const deserializedKey: PublicKey = await SerializerModule.deserializeKey(result?.publicKey as string) as PublicKey;
      expect(deserializedKey).to.deep.equal(friendPublicKey);
    })

    it("should return object with signature if ciphertext had a signature and the challenge has been solved", async () => {
      expect(encryptedChallengeResponse.signature).to.exist;
      
      const result = await wallet.verifyChallengeResponse(encryptedChallengeResponseString);
      expect(result).to.be.an("object");
      expect(result).to.have.property("signature");

      // signature should be a string (serialized)
      expect(result?.signature).to.be.a.string;

      // decode signature
      const deserializedSignature: StandardCiphertext = await SerializerModule.deserializeSignature(result?.signature as string);
      expect(CryptoChecker.isCiphertext(deserializedSignature)).to.be.true;
    })

    it("should return object with signature that is verifiable by claimant if ciphertext had a signature and the challenge has been solved", async () => {
      expect(encryptedChallengeResponse.signature).to.exist;
      
      const result = await wallet.verifyChallengeResponse(encryptedChallengeResponseString);
      expect(result).to.be.an("object");
      expect(result).to.have.property("signature");
      expect(result?.signature).to.be.a.string;

      const isValidSignature = await friendWallet.verifySignature(result?.signature as string);
      expect(isValidSignature).to.not.be.null;
    })

    it("should return null if the challenge has not been solved", async () => {
      const mockSolutionCiphertext: AdvancedCiphertext = {
        ...encryptedChallengeResponse,
        data: encryptedChallenge.data // <-- should be solution
      }

      const mockSolutionCiphertextString: string = await SerializerModule.serializeCiphertext(mockSolutionCiphertext);

      const claimantPublicKey = await wallet.verifyChallengeResponse(mockSolutionCiphertextString);
      expect(claimantPublicKey).to.be.null;
    })
  })
});