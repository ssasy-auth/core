/* eslint-disable @typescript-eslint/no-explicit-any */

import { expect } from "chai";
import { TEST_ERROR } from "../config";
import { CRYPTO_ALGORITHMS, CRYPTO_CONFIG } from "../../src/config";
import { KeyType } from "../../src/interfaces";
import {
  KeyModule, KeyChecker, KEY_ERROR_MESSAGE 
} from "../../src/modules";
import type {
  GenericKey, PassKey, SecretKey, PrivateKey 
} from "../../src/interfaces";

describe("[KeyModule Test Suite]", () => {
  describe("KeyModule", () => {
    describe("generateKey()", () => {
      it("should generate a symmetric key", async () => {
        const testDomain = "test-domain";
        const secretKey: SecretKey = await KeyModule.generateKey({
          domain: testDomain 
        });

        expect(secretKey.type).to.equal(KeyType.SecretKey);
        expect(secretKey.domain).to.equal(testDomain);
        expect(secretKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
      });
    });

    describe("generatePassKey()", () => {
      it("should generate a valid symmetric key from a passphrase", async () => {
        const passphrase = "password";
        const passKey: PassKey = await KeyModule
          .generatePassKey({
            passphrase: passphrase 
          });

        expect(passKey.type).to.equal(KeyType.PassKey);
        expect(passKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
        expect(passKey.salt).to.exist;
      });

      it("should generate the same key from the same passphrase and salt", async () => {
        const passphrase = "password";
        const passKey1: PassKey = await KeyModule.generatePassKey({
          passphrase: passphrase 
        });
        const passKey2: PassKey = await KeyModule.generatePassKey({
          passphrase: passphrase, salt: passKey1.salt 
        });

        const rawPassKey1 = await KeyModule.exportKey(passKey1);
        const rawPassKey2 = await KeyModule.exportKey(passKey2);

        expect(rawPassKey1.salt).to.equal(rawPassKey2.salt);
        expect(rawPassKey1.crypto.k).to.deep.equal(rawPassKey2.crypto.k);
      });

      it("should throw an error if passphrase is not a string", async () => {
        const passphrase = 123;

        try {
          await KeyModule.generatePassKey({
            passphrase: passphrase as any 
          });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(KEY_ERROR_MESSAGE.INVALID_PASSPHRASE);
        }
      });
    })

    describe("generatePrivateKey()", () => {
      it("should generate a private key", async () => {
        const privateKey = await KeyModule.generatePrivateKey();

        expect(privateKey.type).to.equal(KeyType.PrivateKey);
        expect(privateKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.ASYMMETRIC.algorithm.name);
      });
    });

    describe("generatePublicKey()", () => {
      it("should generate a public key from a private key", async () => {
        const privateKey = await KeyModule.generatePrivateKey();
        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        });

        expect(publicKey.type).to.equal(KeyType.PublicKey);
        expect(publicKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.ASYMMETRIC.algorithm.name);
      });

      it("should throw an error if source key is not a valid ECDH key", async () => {
        const privateKey = "invalid-key" as any;

        try {
          await KeyModule.generatePublicKey({
            privateKey 
          });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(KEY_ERROR_MESSAGE.INVALID_ASYMMETRIC_KEY);
        }
      });

      it("should throw an error if source key is not a private key", async () => {
        const privateKey = await KeyModule.generatePrivateKey();
        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        }) as any;

        try {
          await KeyModule.generatePublicKey({
            privateKey: publicKey 
          });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(KEY_ERROR_MESSAGE.INVALID_PRIVATE_KEY);
        }
      });
    });

    describe("generateSharedKey()", () => {
      it("should generate a shared key from a private key in one key pair and a public key in another key pair", async () => {
        const alicePrivateKey = await KeyModule.generatePrivateKey();

        const bobPrivateKey = await KeyModule.generatePrivateKey();
        const bobPublicKey = await KeyModule.generatePublicKey({
          privateKey: bobPrivateKey 
        });

        const sharedKey = await KeyModule.generateSharedKey({
          privateKey: alicePrivateKey,
          publicKey: bobPublicKey
        });

        expect(sharedKey.type).to.equal(KeyType.SharedKey);
        expect(sharedKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
      });

      it("should generate the same shared key when using the same pair of key pairs", async () => {
        const alicePrivateKey = await KeyModule.generatePrivateKey();
        const alicePublicKey = await KeyModule.generatePublicKey({
          privateKey: alicePrivateKey 
        });

        const bobPrivateKey = await KeyModule.generatePrivateKey();
        const bobPublicKey = await KeyModule.generatePublicKey({
          privateKey: bobPrivateKey 
        });

        const sharedKey1 = await KeyModule.generateSharedKey({
          privateKey: alicePrivateKey,
          publicKey: bobPublicKey
        });

        const sharedKey2 = await KeyModule.generateSharedKey({
          privateKey: bobPrivateKey,
          publicKey: alicePublicKey
        });

        // same key type
        expect(sharedKey1.type).to.equal(sharedKey2.type).to.equal(KeyType.SharedKey);

        // same key algorithm
        expect(sharedKey1.crypto.algorithm.name).to.equal(sharedKey2.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);

        const rawSharedKey1 = await KeyModule.exportKey(sharedKey1);
        const rawSharedKey2 = await KeyModule.exportKey(sharedKey2);

        // same key
        expect(rawSharedKey1.crypto.k).to.equal(rawSharedKey2.crypto.k);


      });

      it("should be able to generate a shared key from a private key and a public key in the same key pair", async () => {
        const privateKey = await KeyModule.generatePrivateKey();
        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        });

        const sharedKey = await KeyModule.generateSharedKey({
          privateKey, publicKey 
        });
        expect(sharedKey.type).to.equal(KeyType.SharedKey);
        expect(sharedKey.crypto.algorithm.name).to.equal(CRYPTO_CONFIG.SYMMETRIC.algorithm.name);
      });

      it("should throw an error if private/public key is not a valid ECDH key", async () => {
        const invalidPrivateKey = await KeyModule.generateKey() as any;
        const invalidPublicKey = await KeyModule.generateKey() as any;

        const validPrivateKey = await KeyModule.generatePrivateKey();
        const validPublicKey = await KeyModule.generatePublicKey({
          privateKey: validPrivateKey 
        });

        try {
          await KeyModule.generateSharedKey({
            privateKey: invalidPrivateKey,
            publicKey: validPublicKey
          });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(KEY_ERROR_MESSAGE.INVALID_PRIVATE_KEY);
        }

        try {
          await KeyModule.generateSharedKey({
            privateKey: validPrivateKey,
            publicKey: invalidPublicKey
          });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(KEY_ERROR_MESSAGE.INVALID_PUBLIC_KEY);
        }
      });

      it("should throw an error if the keys have the same type (private or public)", async () => {
        const privateKey1 = await KeyModule.generatePrivateKey() as any;
        const privateKey2 = await KeyModule.generatePrivateKey() as any;

        try {
          await KeyModule.generateSharedKey({
            privateKey: privateKey1,
            publicKey: privateKey2
          });
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(KEY_ERROR_MESSAGE.DUPLICATE_SHARED_KEY_PARAMS);
        }
      });
    })

    describe("exportKey()", () => {
      it("should export SecretKey", async () => {
        const key = await KeyModule.generateKey();
        const rawKey = await KeyModule.exportKey(key);

        // check for key type
        expect(rawKey.type).to.equal(key.type).equal(KeyType.SecretKey);
        // check for jwk key type
        expect(rawKey.crypto.kty).to.equal(CRYPTO_ALGORITHMS.AES.jwk.kty);
        // check for jwk key algorithm
        expect(rawKey.crypto.alg).to.equal(CRYPTO_ALGORITHMS.AES.jwk.algo);
        // check for jwk key usage
        expect(rawKey.crypto.key_ops).to.deep.equal(key.crypto.usages);
        // check for key value
        expect(rawKey.crypto.k).to.exist;

        // check that domain was maintained
        expect(rawKey.domain).to.equal(key.domain);
      });

      it("should export PassKey", async () => {
        const passphrase = "test-passphrase";
        const passKey = await KeyModule.generatePassKey({
          passphrase 
        });
        const rawPassKey = await KeyModule.exportKey(passKey);

        // check for key type
        expect(rawPassKey.type).to.equal(passKey.type).equal(KeyType.PassKey);
        // check for jwk key type
        expect(rawPassKey.crypto.kty).to.equal(CRYPTO_ALGORITHMS.PBKDF2.jwk.kty);
        // check for jwk key algorithm
        expect(rawPassKey.crypto.alg).to.equal(CRYPTO_ALGORITHMS.PBKDF2.jwk.algo);
        // check for jwk key usage
        expect(rawPassKey.crypto.key_ops).to.deep.equal(passKey.crypto.usages);
        // check for key value
        expect(rawPassKey.crypto.k).to.exist;

        // should maintain hash algorithm
        expect(rawPassKey.hash).to.equal(passKey.hash);
        // should maintain salt
        expect(rawPassKey.salt).to.deep.equal(passKey.salt);
        // should maintain iterations
        expect(rawPassKey.iterations).to.equal(passKey.iterations);

        // check that domain was maintained
        expect(rawPassKey.domain).to.equal(passKey.domain);
      });

      it("should export PrivateKey", async () => {
        const privateKey = await KeyModule.generatePrivateKey();
        const rawPrivateKey = await KeyModule.exportKey(privateKey);

        // check for key type
        expect(rawPrivateKey.type).to.equal(privateKey.type).equal(KeyType.PrivateKey);
        // check for jwk key type
        expect(rawPrivateKey.crypto.kty).to.equal(CRYPTO_ALGORITHMS.ECDH.jwk.kty);
        // check for jwk ECDH curve algorithm
        expect(rawPrivateKey.crypto.crv).to.equal(CRYPTO_ALGORITHMS.ECDH.namedCurve);
        // check for jwk key usage
        expect(rawPrivateKey.crypto.key_ops).to.deep.equal(privateKey.crypto.usages);
        // check for key value
        expect(rawPrivateKey.crypto.d).to.exist;
        expect(rawPrivateKey.crypto.x).to.exist;
        expect(rawPrivateKey.crypto.y).to.exist;

        // check that domain was maintained
        expect(rawPrivateKey.domain).to.equal(privateKey.domain);

      });

      it("should export PublicKey", async () => {
        const privateKey = await KeyModule.generatePrivateKey();
        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        });
        const rawPublicKey = await KeyModule.exportKey(publicKey);

        // check for key type
        expect(rawPublicKey.type).to.equal(publicKey.type).equal(KeyType.PublicKey);
        // check for jwk key type
        expect(rawPublicKey.crypto.kty).to.equal(CRYPTO_ALGORITHMS.ECDH.jwk.kty);
        // check for jwk ECDH curve algorithm
        expect(rawPublicKey.crypto.crv).to.equal(CRYPTO_ALGORITHMS.ECDH.namedCurve);
        // check for jwk key usage
        expect(rawPublicKey.crypto.key_ops).to.deep.equal(publicKey.crypto.usages);
        // check for key value
        expect(rawPublicKey.crypto.x).to.exist;
        expect(rawPublicKey.crypto.y).to.exist;

        // check that domain was maintained
        expect(rawPublicKey.domain).to.equal(publicKey.domain);
      });

      it("should throw an error if key is not valid", async () => {
        const key = "invalid-key" as any;

        try {
          await KeyModule.exportKey(key);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(KEY_ERROR_MESSAGE.INVALID_KEY);
        }
      });
    });

    describe("importKey()", () => {
      it("should import SecretKey", async () => {
        const secretKey = await KeyModule.generateKey();
        const rawKey = await KeyModule.exportKey(secretKey);
        const importedKey = await KeyModule.importKey(rawKey);

        expect(importedKey).to.deep.equal(secretKey);
      });

      it("should import PassKey", async () => {
        const passphrase = "test-passphrase";
        const passKey = await KeyModule.generatePassKey({
          passphrase: passphrase 
        });
        const rawPassKey = await KeyModule.exportKey(passKey);
        const importedKey = await KeyModule.importKey(rawPassKey) as PassKey;

        expect(importedKey).to.deep.equal(passKey);
      });

      it("should import PrivateKey", async () => {
        const privateKey = await KeyModule.generatePrivateKey();
        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        });
        const rawPrivateKey = await KeyModule.exportKey(privateKey);
        const importedKey = await KeyModule.importKey(rawPrivateKey) as PrivateKey;

        // deep equal does not work for private keys
        expect(importedKey.type).to.equal(privateKey.type);
        expect(importedKey.domain).to.equal(privateKey.domain);

        const publicKeyFromImportedKey = await KeyModule.generatePublicKey({
          privateKey: importedKey 
        });
        expect(publicKeyFromImportedKey).to.deep.equal(publicKey);


      });

      it("should import PublicKey", async () => {
        const privateKey = await KeyModule.generatePrivateKey();
        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        });
        const rawPublicKey = await KeyModule.exportKey(publicKey);
        const importedKey = await KeyModule.importKey(rawPublicKey);

        expect(importedKey).to.deep.equal(publicKey);
      });

      it("should throw an error if key is not a valid JSON Web Key", async () => {
        const key = "invalid-json-key" as any;

        try {
          await KeyModule.importKey(key);
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(KEY_ERROR_MESSAGE.INVALID_RAW_KEY);
        }
      });
    });
  })

  describe("KeyChecker", () => {
    const { isRawKey, isKey, isSymmetricKey, isAsymmetricKey } = KeyChecker

    describe("isRawKey()", () => {
      it("should return true for a valid raw key", async () => {
        const key = await KeyModule.generateKey()
        const rawKey = await KeyModule.exportKey(key) as GenericKey;

        expect(isRawKey(rawKey)).to.be.true;
      })

      it("should return false for an invalid raw key", async () => {
        const key = await KeyModule.generateKey()
        expect(isRawKey(key)).to.be.false;

        const passKey = await KeyModule.generatePassKey({
          passphrase: "test" 
        })
        expect(isRawKey(passKey)).to.be.false;

        const privateKey = await KeyModule.generatePrivateKey()
        expect(isRawKey(privateKey)).to.be.false;

        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        })
        expect(isRawKey(publicKey)).to.be.false;

      })
    })

    describe("isKey()", () => {
      it("should return true for a valid key", async () => {
        const key = await KeyModule.generateKey()
        expect(isKey(key)).to.be.true;

        const passKey = await KeyModule.generatePassKey({
          passphrase: "test" 
        })
        expect(isKey(passKey)).to.be.true;

        const privateKey = await KeyModule.generatePrivateKey()
        expect(isKey(privateKey)).to.be.true;

        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        })
        expect(isKey(publicKey)).to.be.true;

        const extraPrivateKey = await KeyModule.generatePrivateKey()
        const sharedKey = await KeyModule.generateSharedKey({
          privateKey: extraPrivateKey, publicKey 
        })
        expect(isKey(sharedKey)).to.be.true;
      })

      it("should return false for an invalid key", async () => {
        const { crypto } = await KeyModule.generateKey();
        expect(isKey(crypto as any)).to.be.false;
      })
    })

    describe("isSymmetricKey()", () => {
      it("should return true for a valid symmetric key", async () => {
        const key = await KeyModule.generateKey()
        expect(isSymmetricKey(key)).to.be.true;

        const passKey = await KeyModule.generatePassKey({
          passphrase: "test" 
        })
        expect(isSymmetricKey(passKey)).to.be.true;

        const privateKey = await KeyModule.generatePrivateKey()
        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        })
        const otherPrivateKey = await KeyModule.generatePrivateKey()
        const sharedKey = await KeyModule.generateSharedKey({
          privateKey: otherPrivateKey, publicKey 
        })
        expect(isSymmetricKey(sharedKey)).to.be.true;
      })

      it("should return false for an invalid symmetric key", async () => {
        const privateKey = await KeyModule.generatePrivateKey()
        expect(isSymmetricKey(privateKey)).to.be.false;

        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        })
        expect(isSymmetricKey(publicKey)).to.be.false;
      })
    })

    describe("isAsymmetricKey()", () => {
      it("should return true for a valid asymmetric key", async () => {
        const privateKey = await KeyModule.generatePrivateKey()
        expect(isAsymmetricKey(privateKey)).to.be.true;

        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        })
        expect(isAsymmetricKey(publicKey)).to.be.true;
      })

      it("should return false for an invalid asymmetric key", async () => {
        const key = await KeyModule.generateKey()
        expect(isAsymmetricKey(key)).to.be.false;

        const passKey = await KeyModule.generatePassKey({
          passphrase: "test" 
        })
        expect(isAsymmetricKey(passKey)).to.be.false;

        const privateKey = await KeyModule.generatePrivateKey()
        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        })
        const otherPrivateKey = await KeyModule.generatePrivateKey()
        const sharedKey = await KeyModule.generateSharedKey({
          privateKey: otherPrivateKey, publicKey 
        })
        expect(isAsymmetricKey(sharedKey)).to.be.false;
      })
    })

    describe("isSameKey()", () => {
      it("should return true if two keys are the same", async () => {
        let isSame: boolean;

        const secretKey = await KeyModule.generateKey();
        isSame = await KeyChecker.isSameKey(secretKey, secretKey);
        expect(isSame).to.be.true;

        const passKey = await KeyModule.generatePassKey({
          passphrase: "test-passphrase" 
        });
        isSame = await KeyChecker.isSameKey(passKey, passKey);
        expect(isSame).to.be.true;

        const privateKey = await KeyModule.generatePrivateKey();
        isSame = await KeyChecker.isSameKey(privateKey, privateKey);
        expect(isSame).to.be.true;

        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        });
        isSame = await KeyChecker.isSameKey(publicKey, publicKey);
        expect(isSame).to.be.true;
      })

      it("should return false if two keys are not the same", async () => {
        let isSame: boolean;
        const secretKey = await KeyModule.generateKey();
        const passKey = await KeyModule.generatePassKey({
          passphrase: "test-passphrase" 
        });
        const privateKey = await KeyModule.generatePrivateKey();
        const publicKey = await KeyModule.generatePublicKey({
          privateKey 
        });

        isSame = await KeyChecker.isSameKey(secretKey, passKey);
        expect(isSame).to.be.false;

        isSame = await KeyChecker.isSameKey(privateKey, publicKey);
        expect(isSame).to.be.false;
      })

      it("should throw error if raw key is passed)", async () => {
        const secretKey = await KeyModule.generateKey();
        const rawSecretKey = await KeyModule.exportKey(secretKey);

        try {
          await KeyChecker.isSameKey(rawSecretKey as any, secretKey)
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(KEY_ERROR_MESSAGE.INVALID_KEY);
        }
      })

      it("should throw error if invalid key is passed)", async () => {
        const secretKey = await KeyModule.generateKey();
        
        try {
          await KeyChecker.isSameKey("invalid" as any, secretKey)
          expect.fail(TEST_ERROR.DID_NOT_THROW);
        } catch (e) {
          const error: Error = e as Error;
          expect(error.message).to.equal(KEY_ERROR_MESSAGE.INVALID_KEY);
        }
      })
    });
  })
});