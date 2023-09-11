/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { TEST_ERROR } from "../config";
import { BufferUtil } from "../../src/utils";
import {
  CryptoChecker,
  CryptoModule,
  KeyChecker,
  KeyModule,
  SERIALIZER_ERROR_MESSAGE,
  SerializerChecker,
  SerializerModule 
} from "../../src/modules";
import { Wallet } from "../../src/wallet";
import {
  type AdvancedCiphertext,
  type Challenge,
  type Ciphertext,
  type GenericKey,
  type KeyPair,
  KeyType,
  type PassKey,
  type PrivateKey,
  type PublicKey,
  type RawKey,
  type SecretKey,
  type SharedKey,
  type StandardCiphertext 
} from "../../src/interfaces";

/**
* Returns an array of parameters from a URI
*/
function _extractUriParameters(keyUri: string, prefix: string): string[] {
  // get everything after 'ssasy://key' for example
  const keyStringWithoutPrefix = keyUri.slice(prefix.length);

  // split the string by '&' to get all the properties
  return keyStringWithoutPrefix.split("&");
}

/**
 * Returns true if the string is a valid URL
 */
function _isValidURI(testUri: string): boolean {
  try {
    new URL(testUri);
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * Returns true if the string is a valid utf-8 encoded string with no special characters
 */
function _isValidEncoding(sample: string): boolean {
  const specialCharacters = [ "'", "=", "&", "," ];

  let noSpecialCharacters = true;

  for (const character of specialCharacters) {
    if (sample.includes(character)) {
      noSpecialCharacters = false;
    }
  }
  
  const isUtf8: boolean = BufferUtil.isUtf8String(sample);

  return noSpecialCharacters && isUtf8;
}


describe("[SerializerModule Test Suite]", () => {
  describe("SerializerModule", ()=>{
    
    describe("Key", () => {
      let secretKey: SecretKey;
      let passKey: PassKey;
      let privateKey: PrivateKey;
      let publicKey: PublicKey;
      let sharedKey: SharedKey;
      let rawKey: RawKey;
    
      let keychain: GenericKey[] = [];

      before(async () => {
        secretKey = await KeyModule.generateKey();
        passKey = await KeyModule.generatePassKey({ passphrase: "password" });
        privateKey = await KeyModule.generatePrivateKey();
        publicKey = await KeyModule.generatePublicKey({ privateKey });
        sharedKey = await KeyModule.generateSharedKey({ privateKey, publicKey });
        rawKey = await KeyModule.exportKey(secretKey);

        keychain = [ secretKey, passKey, privateKey, publicKey, sharedKey, rawKey ];
      });

      describe("serializeKey()", () => {
      // a raw key should contain a type, and a crypto object with kty, key_ops and ext
      // a total of 5 properties
        const MIN_KEY_PARAMETERS = 4;

        // a symmetric key contains an alg and k property in addition to the base key properties
        const MIN_SYMMETRIC_KEY_PARAMETERS = MIN_KEY_PARAMETERS + 2;

        // an asymmetric key contains a crv, x, y and d property in addition to the base key properties
        // note: d is only required for private keys
        const MIN_PUBLIC_KEY_PARAMETERS = MIN_KEY_PARAMETERS + 3;
        const MIN_PRIVATE_KEY_PARAMETERS = MIN_KEY_PARAMETERS + 4;

        it("should throw an error if the key is invalid", async () => {
          const invalidKey = "invalid key" as any;

          try {
            await SerializerModule.serializeKey(invalidKey);
            expect.fail(TEST_ERROR.DID_NOT_THROW);
          } catch (e) {
            const error = e as Error;
            expect(error.message).to.equal(SERIALIZER_ERROR_MESSAGE.INVALID_KEY);
          }
        }); 
        
        it("should return a string that starts with `ssasy://key?`", async () => {
          const prefix = "ssasy://key?";  
      
          for (const key of keychain) {
            const keyUri = await SerializerModule.serializeKey(key);
            expect(keyUri).to.be.a("string");
            expect(keyUri.startsWith(prefix)).to.be.true;
          }
        });

        it(`should return a uri with at least ${MIN_KEY_PARAMETERS} properties`, async () => {
          for (const key of keychain) {
            const keyUri = await SerializerModule.serializeKey(key);
            const keyParams = _extractUriParameters(keyUri, SerializerModule.PREFIX.URI.KEY);
            expect(keyParams.length).to.be.greaterThanOrEqual(MIN_KEY_PARAMETERS);
          }
        });
      
        it(`should return a uri with at least ${MIN_SYMMETRIC_KEY_PARAMETERS} properties, if key is symmetric`, async () => {
        
          for (const key of keychain) {
            if(key.type === KeyType.PrivateKey || key.type === KeyType.PublicKey) {
              continue;
            }

            const keyUri = await SerializerModule.serializeKey(key);
            const keyParams = _extractUriParameters(keyUri, SerializerModule.PREFIX.URI.KEY);
            expect(keyParams.length).to.be.greaterThanOrEqual(MIN_SYMMETRIC_KEY_PARAMETERS);
          }
        });
      
        it(`should return a uri with at least ${MIN_PUBLIC_KEY_PARAMETERS} properties, if key is asymmetric`, async () => {
        
          for (const key of keychain) {
            if(key.type !== KeyType.PrivateKey && key.type !== KeyType.PublicKey) {
              continue;
            }

            const keyUri = await SerializerModule.serializeKey(key);
            const keyParams = _extractUriParameters(keyUri, SerializerModule.PREFIX.URI.KEY);

            if(key.type === KeyType.PrivateKey) {
              expect(keyParams.length, "number of private key properties").to.be.greaterThanOrEqual(MIN_PRIVATE_KEY_PARAMETERS);
            } else {
              expect(keyParams.length, "number of public key properties").to.be.greaterThanOrEqual(MIN_PUBLIC_KEY_PARAMETERS);
            }
          }
        });

        it("should not return a uri with an undefined param value", async () => {
          for (const key of keychain) {
            const keyUri = await SerializerModule.serializeKey(key);
            const keyParams = _extractUriParameters(keyUri, SerializerModule.PREFIX.URI.KEY);

            for (const param of keyParams) {
              const value = param.split("=")[1];
              expect(value).to.not.equal("undefined");
            }
          }
        });

        it("should encode uri param values", async () => {
          for (const key of keychain) {
            const keyUri = await SerializerModule.serializeKey(key);
            const keyParams = _extractUriParameters(keyUri, SerializerModule.PREFIX.URI.KEY);

            for(const property of keyParams) {
              const value = property.split("=")[1];
            
              // check if value is encoded
              expect(_isValidEncoding(value)).to.be.true;
            }
          }
        });

        it("should return a valid URI", async () => {
          for (const key of keychain) {
            const keyUri = await SerializerModule.serializeKey(key);
            
            // check if URI is valid SSASy URI
            expect(SerializerChecker.isKeyUri(keyUri)).to.be.true;

            // check if URI is valid URL
            expect(_isValidURI(keyUri)).to.be.true;
          }
        });
      });

      describe("deserializeKey()", () => {
        let serializedKeyChain: string[];
        let serializedRawKey: string;
        let serializedSecretKey: string;
        let serializedPassphraseKey: string;
        let serializedPrivateKey: string;
        let serializedPublicKey: string;

        before(async () => {
          serializedRawKey = await SerializerModule.serializeKey(rawKey);
          serializedSecretKey = await SerializerModule.serializeKey(secretKey);
          serializedPassphraseKey = await SerializerModule.serializeKey(passKey);
          serializedPrivateKey = await SerializerModule.serializeKey(privateKey);
          serializedPublicKey = await SerializerModule.serializeKey(publicKey);

          serializedKeyChain = [
            serializedRawKey,
            serializedSecretKey,
            serializedPassphraseKey,
            serializedPrivateKey,
            serializedPublicKey
          ];
        });

        it("should throw an error if the string is an invalid key", async () => {
          const invalidPublicKeyString = "invalid key string";

          try {
            await SerializerModule.deserializeKey(invalidPublicKeyString);
            expect.fail(TEST_ERROR.DID_NOT_THROW);
          } catch (e) {
            const error = e as Error;
            expect(error.message).to.equal(SERIALIZER_ERROR_MESSAGE.INVALID_KEY_STRING);
          }
        });

        it("should deserialize and return a key for all types", async () => {
          for(const serializedKey of serializedKeyChain) {
            const key = await SerializerModule.deserializeKey(serializedKey);
            expect(KeyChecker.isKey(key)).to.be.true;

          }
        });

        it("should return a raw key if config.raw is true", async() => {
          for(const serializedKey of serializedKeyChain) {
            const key = await SerializerModule.deserializeKey(serializedKey, { raw: true });
            expect(KeyChecker.isRawKey(key)).to.be.true;
          }
        });
      });
    });

    describe("Challenge", () => {
      let nonce: string;
      let verifierPublicKey: PublicKey;
      let claimantPublicKey: PublicKey;
      let challenge: Challenge;

      before(async () => {
      // set random number
        const nonceBufferArray = CryptoModule.generateNonce();
        nonce = BufferUtil.BufferToString(nonceBufferArray);
        // set verifier's public key
        verifierPublicKey = await KeyModule.generatePublicKey({ privateKey: await KeyModule.generatePrivateKey() });
        // set claimant's crypto key
        claimantPublicKey = await KeyModule.generatePublicKey({ privateKey: await KeyModule.generatePrivateKey() });
        // set challenge
        challenge = {
          nonce,
          timestamp: Date.now(),
          verifier: verifierPublicKey,
          claimant: claimantPublicKey 
        } as Challenge;
      });

      describe("serializeChallenge()", () => {
      // a challenge has a nonce, timestamp, verifier and claimant property
        const MIN_CHALLENGE_PARAMETERS = 4;

        // a challenge-response has all challenge properties including a solution
        const MIN_CHALLENGE_RESPONSE_PARAMETERS = MIN_CHALLENGE_PARAMETERS + 1;

        it("should return a string that starts with `ssasy://challenge?`", async () => {
          const challengeUri = await SerializerModule.serializeChallenge(challenge);
          expect(challengeUri).to.be.a.string;

          expect(challengeUri.startsWith(SerializerModule.PREFIX.URI.CHALLENGE)).to.be.true;
        });

        it(`should return a uri with at least ${MIN_CHALLENGE_PARAMETERS} properties`, async () => {
          const challengeUri = await SerializerModule.serializeChallenge(challenge);
          const challengeParams = _extractUriParameters(challengeUri, SerializerModule.PREFIX.URI.CHALLENGE);

          expect(challengeParams.length).to.equal(MIN_CHALLENGE_PARAMETERS);
        });

        it(`should return a uri with at least ${MIN_CHALLENGE_RESPONSE_PARAMETERS} properties if solution is present`, async () => {
          const challengeResponse = { ...challenge, solution: "test" } as Challenge;
          const challengeResponseUri = await SerializerModule.serializeChallenge(challengeResponse);
          const challengeResponseParams = _extractUriParameters(challengeResponseUri, SerializerModule.PREFIX.URI.CHALLENGE);

          expect(challengeResponseParams.length).to.equal(MIN_CHALLENGE_RESPONSE_PARAMETERS);
        });

        it("should not return a uri with an undefined param value", async () => {
          const challenges: Challenge[] = [
            challenge,
            { ...challenge, solution: "test" } as Challenge // challenge-response
          ];

          for(const challenge of challenges) {
          
            const challengeUri = await SerializerModule.serializeChallenge(challenge);
            const challengeParams = _extractUriParameters(challengeUri, SerializerModule.PREFIX.URI.CHALLENGE);

            for (const param of challengeParams) {
              const value = param.split("=")[1];
              expect(value).to.not.equal("undefined");
            }
          }
        });

        it("should encode uri param values", async () => {
          const challengeResponse = { ...challenge, solution: "test" } as Challenge;
          const challengeResponseUri = await SerializerModule.serializeChallenge(challengeResponse);
          const challengeResponseParams = _extractUriParameters(challengeResponseUri, SerializerModule.PREFIX.URI.CHALLENGE);

          for(const property of challengeResponseParams) {
            const value = property.split("=")[1];
          
            // check if value is encoded
            expect(_isValidEncoding(value)).to.be.true;
          }
        });

        /**
       * @todo
       * 1. should throw an error if invalid nonce is not a Uint8Array
       * 2. should throw an error if invalid timestamp is not a number
       * 3. should throw an error if invalid verifier is not a public key object
       */
        it("should throw an error if invalid challenge is passed", async () => {
          const invalidChallenges: any[] = [
            { ...challenge, nonce: BufferUtil.BufferToString(new Uint8Array(0)) }, // empty nonce not allowed
            { ...challenge,timestamp: "invalid timestamp" }, // timestamp needs to be a number
            { ...challenge, verifier: "invalid verifier" },  // verifier needs to be a public key object
            { ...challenge, claimant: "invalid claimant" }  // claimant needs to be a public key object
          ];

          for(const invalidChallenge of invalidChallenges) {
            try {
              await SerializerModule.serializeChallenge(invalidChallenge);
              expect.fail(TEST_ERROR.DID_NOT_THROW);
            } catch (e) {
              const error = e as Error;
              expect(error.message).to.equal(SERIALIZER_ERROR_MESSAGE.INVALID_CHALLENGE);
            }
          }
        });
      });

      describe("deserializeChallenge()", () => {
        let challenge: Challenge;
        let challengeUri: string;

        before(async () => {
          // set random number
          const nonceBufferArray = CryptoModule.generateNonce();
          nonce = BufferUtil.BufferToString(nonceBufferArray);
          // set verifier's public key
          const verifierPublicKey = await KeyModule.generatePublicKey({ privateKey: await KeyModule.generatePrivateKey() });
          // set claimant's crypto key
          const claimantPublicKey = await KeyModule.generatePublicKey({ privateKey: await KeyModule.generatePrivateKey() });
      
          // set challenge
          challenge = {
            nonce,
            timestamp: Date.now(),
            verifier: verifierPublicKey,
            claimant: claimantPublicKey,
            solution: "test" 
          } as Challenge;

          // set challenge string
          challengeUri = await SerializerModule.serializeChallenge(challenge);
        });
      
        it("should convert challenge string (uri) to challenge object", async () => {
        // convert the string back to a challenge object
          const challengeObject = await SerializerModule.deserializeChallenge(challengeUri);

          expect(challengeObject.nonce).to.deep.equal(challenge.nonce);
          expect(challengeObject.timestamp).to.equal(challenge.timestamp);
          expect(challengeObject.verifier).to.deep.equal(challenge.verifier);
          expect(challengeObject.claimant).to.deep.equal(challenge.claimant);
          expect(challengeObject.solution).to.equal(challenge.solution);
        });

        it("should handle a challenge with no solution", async () => {
        // convert the challenge to a string
          const challengeUri = await SerializerModule.serializeChallenge(challenge); // <nonce>::<timestamp>::<verifier>::<claimant>::<solution>

          // convert the string back to a challenge object
          const challengeObject = await SerializerModule.deserializeChallenge(challengeUri);

          expect(challengeObject.nonce).to.deep.equal(challenge.nonce);
          expect(challengeObject.timestamp).to.equal(challenge.timestamp);
          expect(challengeObject.verifier).to.deep.equal(challenge.verifier);
          expect(challengeObject.claimant).to.deep.equal(challenge.claimant);
        });

        /**
       * @todo
       * 1. should throw an error if invalid nonce is not a Uint8Array
       * 2. should throw an error if invalid timestamp is not a number
       * 3. should throw an error if invalid verifier is not a public key object
       */
        it("should throw an error if invalid challenge string is passed", async () => {
          const invalidChallengeStrings = [
            "invalid",
            "invalid-nonce::invalid-timestamp::invalid-verifier::invalid-claimant::invalid-solution",
            "ssasy://challenge?invalid-nonce::invalid-timestamp::invalid-verifier::invalid-claimant::invalid-solution",
            "ssasy://challenge?nonce=undefined&timestamp=undefined&verifier=undefined&claimant=undefined&solution=undefined"
          ];

          for(const invalidChallengeString of invalidChallengeStrings) {
            try {
              await SerializerModule.deserializeChallenge(invalidChallengeString);
              expect.fail(TEST_ERROR.DID_NOT_THROW);
            } catch (error) {

              expect((error as Error).message).be.oneOf([
                SERIALIZER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING,
                SERIALIZER_ERROR_MESSAGE.LEGACY_INVALID_CHALLENGE_STRING
              ]);
            }
          }
        });
      });
    });

    describe("Ciphertext", () => {
      const plaintext = "test plaintext";
    
      let verifierKeyPair: KeyPair;
      let claimantKeyPair: KeyPair;
      let sharedKey: SharedKey;
    
      let ciphertexts: Ciphertext[];
      let standardCiphertext: StandardCiphertext;
      let standardCiphertextWithSalt: StandardCiphertext;
      let advancedCiphertext: AdvancedCiphertext;
      let advancedCiphertextWithSignature: AdvancedCiphertext;

      before(async () => {
      // set verifier's key pair
        verifierKeyPair = {} as KeyPair;
        verifierKeyPair.private = await KeyModule.generatePrivateKey();
        verifierKeyPair.public = await KeyModule.generatePublicKey({ privateKey: verifierKeyPair.private });

        // set claimant's key pair
        claimantKeyPair = {} as KeyPair;
        claimantKeyPair.private = await KeyModule.generatePrivateKey();
        claimantKeyPair.public = await KeyModule.generatePublicKey({ privateKey: claimantKeyPair.private });

        // set shared key
        sharedKey = await KeyModule.generateSharedKey({ privateKey: verifierKeyPair.private, publicKey: claimantKeyPair.public });

        // set standard ciphertext
        standardCiphertext = await CryptoModule.encrypt(sharedKey, plaintext);

        // set standard ciphertext with salt
        standardCiphertextWithSalt = await CryptoModule.encrypt(
          "password",
          plaintext
        );

        // set advanced ciphertext
        advancedCiphertext = await CryptoModule.encrypt(
          sharedKey, 
          plaintext, 
          verifierKeyPair.public, 
          claimantKeyPair.public
        );

        // set advanced ciphertext with signature
        const privateKeyUri: string = await SerializerModule.serializeKey(verifierKeyPair.private);
        const claimantWallet = new Wallet(privateKeyUri);
        const signatureUri: string = await claimantWallet.generateSignature(plaintext);
        
        advancedCiphertextWithSignature = {
          ...advancedCiphertext,
          signature: await SerializerModule.deserializeSignature(signatureUri) 
        };

        // set ciphertexts
        ciphertexts = [
          standardCiphertext,
          standardCiphertextWithSalt,
          advancedCiphertext,
          advancedCiphertextWithSignature
        ];
      });

      describe("serializeCiphertext()", () => {
      // a standard ciphertext has a data and iv property
        const MIN_STANDARD_CIPHERTEXT_PARAMETERS = 2;
        // a standard ciphertext derived from a passphrase has an additional salt property
        const MIN_STANDARD_CIPHERTEXT_PARAMETERS_WITH_SALT = MIN_STANDARD_CIPHERTEXT_PARAMETERS + 1;
        // an advanced ciphertext has a sender and recipient property
        const MIN_ADVANCED_CIPHERTEXT_PARAMETERS = MIN_STANDARD_CIPHERTEXT_PARAMETERS + 2;
        // an advanced ciphertext with a signature has an additional signature property
        const MIN_ADVANCED_CIPHERTEXT_PARAMETERS_WITH_SIGNATURE = MIN_ADVANCED_CIPHERTEXT_PARAMETERS + 1;

        it("should return a string that starts with `ssasy://ciphertext?`", async () => {
          for(const ciphertext of ciphertexts) {
            const ciphertextUri = await SerializerModule.serializeCiphertext(ciphertext);
            expect(ciphertextUri).to.be.a("string");
            expect(ciphertextUri.startsWith(SerializerModule.PREFIX.URI.CIPHERTEXT)).to.be.true;
          }
        });

        it(`should return a uri with at least ${MIN_STANDARD_CIPHERTEXT_PARAMETERS} properties`, async () => {
          for (const ciphertext of ciphertexts) {
            const ciphertextUri = await SerializerModule.serializeCiphertext(ciphertext);
            const ciphertextParams = _extractUriParameters(ciphertextUri, SerializerModule.PREFIX.URI.CIPHERTEXT);
            expect(ciphertextParams.length).to.be.greaterThanOrEqual(MIN_STANDARD_CIPHERTEXT_PARAMETERS);
          }
        });

        it(`should return a uri with at least ${MIN_STANDARD_CIPHERTEXT_PARAMETERS_WITH_SALT} properties if salt is present`, async () => {
          const ciphertextUri = await SerializerModule.serializeCiphertext(standardCiphertextWithSalt);
          const ciphertextParams = _extractUriParameters(ciphertextUri, SerializerModule.PREFIX.URI.CIPHERTEXT);
          expect(ciphertextParams.length).to.be.greaterThanOrEqual(MIN_STANDARD_CIPHERTEXT_PARAMETERS_WITH_SALT);
        });

        it(`should return a uri with at least ${MIN_ADVANCED_CIPHERTEXT_PARAMETERS} properties if sender and recipient are present`, async () => {
          const ciphertextUri = await SerializerModule.serializeCiphertext(advancedCiphertext);
          const ciphertextParams = _extractUriParameters(ciphertextUri, SerializerModule.PREFIX.URI.CIPHERTEXT);
          expect(ciphertextParams.length).to.be.greaterThanOrEqual(MIN_ADVANCED_CIPHERTEXT_PARAMETERS);
        });

        it(`should return a uri with at least ${MIN_ADVANCED_CIPHERTEXT_PARAMETERS_WITH_SIGNATURE} properties if signature is present`, async () => {
          const ciphertextUri = await SerializerModule.serializeCiphertext(advancedCiphertextWithSignature);
          const ciphertextParams = _extractUriParameters(ciphertextUri, SerializerModule.PREFIX.URI.CIPHERTEXT);
          expect(ciphertextParams.length).to.be.greaterThanOrEqual(MIN_ADVANCED_CIPHERTEXT_PARAMETERS_WITH_SIGNATURE);
        });

        it("should not return a uri with an undefined param value", async () => {
          for(const ciphertext of ciphertexts) {
            const ciphertextUri = await SerializerModule.serializeCiphertext(ciphertext);
            const ciphertextParams = _extractUriParameters(ciphertextUri, SerializerModule.PREFIX.URI.CIPHERTEXT);

            for (const param of ciphertextParams) {
              const value = param.split("=")[1];
              expect(value).to.not.equal("undefined");
            }
          }
        });

        it("should encode nested signature, verifier and claimant properties if present", async () => {
          const ciphertextUri = await SerializerModule.serializeCiphertext(advancedCiphertextWithSignature);
          const ciphertextParams = _extractUriParameters(ciphertextUri, SerializerModule.PREFIX.URI.CIPHERTEXT);

          for(const property of ciphertextParams) {
            const value = property.split("=")[1];

            // check if value is encoded
            expect(_isValidEncoding(value)).to.be.true;
          }
        });

        it("should encode uri param values", async () => {
          for (const ciphertext of ciphertexts) {
            const ciphertextUri = await SerializerModule.serializeCiphertext(ciphertext);
            const ciphertextParams = _extractUriParameters(ciphertextUri, SerializerModule.PREFIX.URI.CIPHERTEXT);

            for(const property of ciphertextParams) {
              const value = property.split("=")[1];
            
              // check if value is encoded
              expect(_isValidEncoding(value)).to.be.true;
            }
          }
        });

        it("should throw an error if invalid ciphertext is passed", async () => {
          const invalidCiphertexts = [
            "invalid",
            { ...standardCiphertext, data: 123 },
            { ...standardCiphertext, sender: "invalid-public-key" },
            { ...advancedCiphertext, data: 123 }, // invalid data
            { ...advancedCiphertext, sender: "invalid-public-key" } // invalid sender
          ];

          for (const invalidCiphertext of invalidCiphertexts) {
            try {
              await SerializerModule.serializeCiphertext(invalidCiphertext as any);
              expect.fail(TEST_ERROR.DID_NOT_THROW);
            } catch (e) {
              const error = e as Error;
              expect(error.message).to.equal(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT);
            }
          }
        });
      });

      describe("deserializeCiphertext()", () => {
        let ciphertextStrings: string[];
        let standardCiphertextString: string;
        let standardCiphertextWithSaltString: string;
        let advancedCiphertextString: string;
        let advancedCiphertextWithSignatureString: string;
        
        let legacyCiphertextString: string;
        let legacyAdvancedCiphertextString: string; // with signature

        before(async () => {
          standardCiphertextString = await SerializerModule.serializeCiphertext(standardCiphertext);
          standardCiphertextWithSaltString = await SerializerModule.serializeCiphertext(standardCiphertextWithSalt);
          advancedCiphertextString = await SerializerModule.serializeCiphertext(advancedCiphertext);
          advancedCiphertextWithSignatureString = await SerializerModule.serializeCiphertext(advancedCiphertextWithSignature);

          // set legacy ciphertext
          const standardCiphertextCopy = { ...standardCiphertext };
          legacyCiphertextString = JSON.stringify(standardCiphertextCopy);
          
          // set legacy advanced ciphertext
          const advancedCiphertextCopy: any = { ...advancedCiphertextWithSignature };
          advancedCiphertextCopy.sender = advancedCiphertextCopy.sender ? await KeyModule.exportKey(advancedCiphertextCopy.sender) : undefined;
          advancedCiphertextCopy.recipient = advancedCiphertextCopy.recipient ? await KeyModule.exportKey(advancedCiphertextCopy.recipient) : undefined;
          advancedCiphertextCopy.signature = advancedCiphertextCopy.signature ? JSON.stringify(advancedCiphertextCopy.signature) : undefined;
          legacyAdvancedCiphertextString = JSON.stringify(advancedCiphertextCopy);

          ciphertextStrings = [
            standardCiphertextString,
            standardCiphertextWithSaltString,
            advancedCiphertextString,
            advancedCiphertextWithSignatureString
          ];
        });

        it("should return a ciphertext object", async () => {

          for (const ciphertextUri of ciphertextStrings) {
            const ciphertext = await SerializerModule.deserializeCiphertext(ciphertextUri);
            expect(CryptoChecker.isCiphertext(ciphertext)).to.be.true;
          }
        });

        it("should return ciphertext with salt if standard ciphertext with salt was serialized", async () => {
          const deserializedStandardCipherTextWithSalt = await SerializerModule.deserializeCiphertext(standardCiphertextWithSaltString) as StandardCiphertext;
          expect(deserializedStandardCipherTextWithSalt.salt).to.equal(standardCiphertextWithSalt.salt);
        });

        it("should return ciphertext with sender and recipient if advanced ciphertext was serialized", async () => {
          const deserializedAdvancedCipherText = await SerializerModule.deserializeCiphertext(advancedCiphertextString) as AdvancedCiphertext;
          expect(deserializedAdvancedCipherText.sender).to.deep.equal(advancedCiphertext.sender);
          expect(deserializedAdvancedCipherText.recipient).to.deep.equal(advancedCiphertext.recipient);
        });

        it("should return ciphertext with signature if advanced ciphertext with signature was serialized", async () => {
          const deserializedAdvancedCipherTextWithSignature = await SerializerModule.deserializeCiphertext(advancedCiphertextWithSignatureString) as AdvancedCiphertext;
          expect(deserializedAdvancedCipherTextWithSignature.signature?.data).to.deep.equal(advancedCiphertextWithSignature.signature?.data);
          expect(deserializedAdvancedCipherTextWithSignature.signature?.iv).to.deep.equal(advancedCiphertextWithSignature.signature?.iv);
        });

        it("should support legacy ciphertexts", async () => {
          const legacyCiphertexts = [
            legacyCiphertextString,
            legacyAdvancedCiphertextString
          ];

          for (const legacyCiphertext of legacyCiphertexts) {
            const ciphertext = await SerializerModule.deserializeCiphertext(legacyCiphertext);
            expect(CryptoChecker.isCiphertext(ciphertext)).to.be.true;
          }
        });

        it("should throw an error if invalid ciphertext uri is passed", async () => {
          const invalidCiphertextStrings = [
            "invalid",
            JSON.stringify({ ...advancedCiphertext, data: 123 }),
            JSON.stringify({ ...advancedCiphertext, sender: "invalid-public-key" }),
            "ssasy://ciphertext?data=undefined&iv=undefined&sender=undefined&recipient=undefined&signature=undefined",
            "ssasy://key?type=public-key&c_crv=undefined&c_x=undefined&c_y=undefined&c_kty=undefined&c_key_ops=undefined&c_ext=undefined",
            advancedCiphertextString.replace(/data=[^&]*/g, "data=undefined"), // invalid data
            advancedCiphertextString.replace(/&sender=[^&]*/g, "&sender=undefined"), // invalid sender
            advancedCiphertextWithSignatureString.replace(/&signature=[^&]*/g, "&signature=invalid") // invalid signature
          ];

          for (const invalidCiphertextString of invalidCiphertextStrings) {
            try {
              await SerializerModule.deserializeCiphertext(invalidCiphertextString);
              expect.fail(TEST_ERROR.DID_NOT_THROW);
            } catch (error) {

              expect((error as Error).message).be.oneOf([
                SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING,
                SERIALIZER_ERROR_MESSAGE.LEGACY_INVALID_CIPHERTEXT_STRING
              ]);
            }
          }
        });
      });
    });

    describe("Signature", () => {
      let wallet: Wallet;
      let signature: StandardCiphertext;

      before(async () => {
        const privateKey = await KeyModule.generatePrivateKey();
        const privateKeyUri = await SerializerModule.serializeKey(privateKey);
        wallet = new Wallet(privateKeyUri);

        const plaintext = "test plaintext";
        const signatureUri: string = await wallet.generateSignature(plaintext);
        signature = await SerializerModule.deserializeSignature(signatureUri);
      });

      describe("serializeSignature()", () => {
        // a standard ciphertext has a data and iv property
        const MIN_SIGNATURE_PARAMETERS = 2;

        it("should return a string that starts with `ssasy://signature?`", async () => {
          const signatureUri = await SerializerModule.serializeSignature(signature);
          expect(signatureUri).to.be.a("string");
          expect(signatureUri.startsWith(SerializerModule.PREFIX.URI.SIGNATURE)).to.be.true;
        });

        it(`should return a uri with at least ${MIN_SIGNATURE_PARAMETERS} properties`, async () => {
          const signatureUri = await SerializerModule.serializeSignature(signature);
          const signatureParameters = _extractUriParameters(signatureUri, SerializerModule.PREFIX.URI.SIGNATURE);
          expect(signatureParameters.length).to.be.greaterThanOrEqual(MIN_SIGNATURE_PARAMETERS);
        });

        it("should not return a uri with an undefined param value", async () => {
          const signatureUri = await SerializerModule.serializeSignature(signature);
          const signatureParameters = _extractUriParameters(signatureUri, SerializerModule.PREFIX.URI.SIGNATURE);

          for (const param of signatureParameters) {
            const value = param.split("=")[1];
            expect(value).to.not.equal("undefined");
          }
        });

        it("should encode uri param values", async () => {
          const signatureUri = await SerializerModule.serializeSignature(signature);
          const signatureParameters = _extractUriParameters(signatureUri, SerializerModule.PREFIX.URI.SIGNATURE);

          for(const property of signatureParameters) {
            const value = property.split("=")[1];
          
            // check if value is encoded
            expect(_isValidEncoding(value)).to.be.true;
          }
        });

        it("should throw an error if invalid ciphertext is passed", async () => {
          const invalidCiphertexts = [
            "invalid",
            { ...signature, data: 123 },
            { ...signature, sender: "invalid-public-key" },
            { ...signature, data: 123 }, // invalid data
            { ...signature, sender: "invalid-public-key" }, // invalid sender
            "ssasy://signature?data=undefined&iv=undefined",
            "ssasy://ciphertext?data=undefined&iv=undefined",
            "ssasy://key?type=public-key&c_crv=undefined&c_x=undefined&c_y=undefined&c_kty=undefined&c_key_ops=undefined&c_ext=undefined"
          ];

          for (const invalidCiphertext of invalidCiphertexts) {
            try {
              await SerializerModule.serializeCiphertext(invalidCiphertext as any);
              expect.fail(TEST_ERROR.DID_NOT_THROW);
            } catch (e) {
              const error = e as Error;
              expect(error.message).to.equal(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT);
            }
          }
        });
      });

      describe("deserializeSignature()", () => {
        let signatureUri: string;

        before(async () => {
          signatureUri = await SerializerModule.serializeSignature(signature);
        });

        it("should return a signature object", async () => {
          const deserializedSignature = await SerializerModule.deserializeSignature(signatureUri);
          expect(CryptoChecker.isCiphertext(deserializedSignature)).to.be.true;
        });

        it("should throw an error if invalid ciphertext string is passed", async () => {
          const invalidCiphertextStrings = [
            "invalid",
            JSON.stringify({ ...signature, data: 123 }),
            JSON.stringify({ ...signature, sender: "invalid-public-key" })
          ];

          for (const invalidCiphertextString of invalidCiphertextStrings) {
            try {
              await SerializerModule.deserializeCiphertext(invalidCiphertextString);
              expect.fail(TEST_ERROR.DID_NOT_THROW);
            } catch (error) {
              
              expect((error as Error).message).be.oneOf([
                SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING,
                SERIALIZER_ERROR_MESSAGE.LEGACY_INVALID_CIPHERTEXT_STRING
              ]);
            }
          }
        });
      });
    });
  });

  describe("SerializerChecker", () => {
    // test key resources
    let privateKey: PrivateKey;
    let publicKey: PublicKey;
    let publicKeyUri: string;
    let rawPublicKey: RawKey;

    // test ciphertext resources
    let ciphertext: Ciphertext;
    let ciphertextUri: string;
    
    // test signature resources
    let signature: Ciphertext;
    let signatureUri: string;

    before(async () => {
      privateKey = await KeyModule.generatePrivateKey();
      publicKey = await KeyModule.generatePublicKey({ privateKey });
      publicKeyUri = await SerializerModule.serializeKey(publicKey);
      rawPublicKey = await KeyModule.exportKey(publicKey);

      ciphertext = await CryptoModule.encrypt("test passphrase", "test plaintext");
      ciphertextUri = await SerializerModule.serializeCiphertext(ciphertext);

      signature = await CryptoModule.sign(privateKey, "test plaintext");
      signatureUri = await SerializerModule.serializeSignature(signature);
    });
    
    describe("isKeyUri()", () => {
      it("should return false if uri is not a key uri", () => {
        const rawPublicKeyString = JSON.stringify(rawPublicKey);
        expect(SerializerChecker.isKeyUri(rawPublicKeyString)).to.be.false;
        
        expect(SerializerChecker.isKeyUri(ciphertextUri)).to.be.false;
        expect(SerializerChecker.isKeyUri(signatureUri)).to.be.false;
      });

      it("should return true if uri is a key uri", () => {
        expect(SerializerChecker.isKeyUri(publicKeyUri)).to.be.true;
      });

      it("should return false if uri is a key but it does not match provided key type", () => {
        expect(SerializerChecker.isKeyUri(publicKeyUri, { type: KeyType.SecretKey })).to.be.false;
        expect(SerializerChecker.isKeyUri(publicKeyUri, { type: KeyType.PassKey })).to.be.false;
        expect(SerializerChecker.isKeyUri(publicKeyUri, { type: KeyType.SharedKey })).to.be.false;
        expect(SerializerChecker.isKeyUri(publicKeyUri, { type: KeyType.PrivateKey })).to.be.false;
        expect(SerializerChecker.isKeyUri(publicKeyUri, { type: KeyType.SecretKey })).to.be.false;
      });

      it("should return true if uri is a key and it matches provided key type", () => {
        expect(SerializerChecker.isKeyUri(publicKeyUri, { type: KeyType.PublicKey })).to.be.true;
      });
    });

    describe("isCiphertextUri()", () => {

      it("should return false if uri is not a ciphertext uri", () => {
        const rawPublicKeyString = JSON.stringify(rawPublicKey);
        expect(SerializerChecker.isCiphertextUri(rawPublicKeyString)).to.be.false;
        
        expect(SerializerChecker.isCiphertextUri(publicKeyUri)).to.be.false;
        expect(SerializerChecker.isCiphertextUri(signatureUri)).to.be.false;
      });

      it("should return true if uri is a ciphertext uri", () => {
        expect(SerializerChecker.isCiphertextUri(ciphertextUri)).to.be.true;
      });
    });

    describe("isSignatureUri()", () => {
      it("should return false if uri is not a signature uri", () => {
        const rawPublicKeyString = JSON.stringify(rawPublicKey);
        expect(SerializerChecker.isSignatureUri(rawPublicKeyString)).to.be.false;
        
        expect(SerializerChecker.isSignatureUri(publicKeyUri)).to.be.false;
        expect(SerializerChecker.isSignatureUri(ciphertextUri)).to.be.false;
      });

      it("should return true if uri is a signature uri", () => {
        expect(SerializerChecker.isSignatureUri(signatureUri)).to.be.true;
      });
    });

  });
});