/**
 * Wallet
 * 
 * The purpose of this class is to abstract the key management and cryptographic operations.
 * In order to be as developer-friendly as possible, the class exposes a set of methods that
 * should be easy to use and understand. This is acheived by establishing a "uniform"
 * representation of the data that is passed to (and returned) from the methods.
 * 
 * This means that all the methods accept and return SSASy resources, represented as URIs. 
 * The developer can pass a SSASy resource URI to a method and the method can return
 * a SSASy URI resource. Using URIs as the only representation of the data is useful
 * especially useful when the developer wants to store the data in a database or send it
 * over the network.
 */

import { KeyType } from "./interfaces";
import {
  SerializerModule,
  ChallengeModule,
  ChallengeChecker,
  CryptoModule,
  CryptoChecker,
  CRYPTO_ERROR_MESSAGE,
  KeyModule,
  KeyChecker,
  SerializerChecker
} from "./modules";
import type {
  Ciphertext,
  AdvancedCiphertext,
  PrivateKey,
  PublicKey,
  StandardCiphertext,
  Challenge,
  SharedKey,
  RawKey
} from "./interfaces";

export const WALLET_ERROR_MESSAGE = {
  INVALID_CONSTRUCTOR_PARAMS: "Key is missing from constructor parameters",
  INVALID_KEY: "Key is invalid or not supported by this method",
  INVALID_PAYLOAD: "Payload is invalid (must be a string)",
  INVALID_CIPHERTEXT: "Ciphertext is invalid",
  INVALID_CIPHERTEXT_ORIGIN: "Ciphertext sender or recipient does not match the wallet's public key",
  INVALID_CIPHERTEXT_SIGNATURE: "Ciphertext signature is invalid or missing",
  INVALID_CHALLENGE_ORIGIN: "Challenge verifier or claimant does not match the wallet's public key",
  INVALID_SIGNATURE_ORIGIN: "Signature's parties do not match the challenge's parties",
  MISSING_KEY: "Key is missing",
  MISSING_PAYLOAD: "Payload is missing",
  MISSING_CIPHERTEXT: "Ciphertext is missing",
  MISSING_CIPHERTEXT_CHALLENGE: "Ciphertext is missing challenge",
  MISSING_CIPHERTEXT_PARTIES: "Ciphertext is missing sender or recipient",
  MISSING_SIGNATURE_MESSAGE: "Signature message is missing"
};

/**
 * An encrypted payload containing data (challenge) with the sender and recipient public keys.
 */
interface EncryptedChallenge extends Omit<AdvancedCiphertext, "sender" | "recipient"> {
	sender: PublicKey;
	recipient: PublicKey;
}

/**
 * An object with the claimant's public key and the signature of the challenge-response (if it was solved correctly)
 */
export type ChallengeResult = { publicKey: string; signature?: string | undefined };

/**
 * Returns ciphertext if it contains the correct sender and recipient
 */
function _isEncryptedChallenge(ciphertext: unknown): EncryptedChallenge {
  if (!ciphertext) {
    throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
  }

  const challengeCiphertext = ciphertext as AdvancedCiphertext;

  if (!challengeCiphertext.sender || !challengeCiphertext.recipient) {
    throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_PARTIES);
  }

  if (!challengeCiphertext.data) {
    throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
  }

  if (!CryptoChecker.isCiphertext(challengeCiphertext)) {
    throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
  }

  return challengeCiphertext as EncryptedChallenge;
}

/**
 * @class Wallet
 * @classdesc Abstracts the key management and cryptographic operations
 * @param {string} privateKey - a private key uri
 */
export class Wallet {
  /**
	 * Initiates wallet.
	 *
	 * @param privateKey - private key uri
	 */
  constructor(privateKeyUri: string) {
    // throw error if private key is missing
    if (!privateKeyUri) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CONSTRUCTOR_PARAMS);
    }

    // throw error if private key is not a string
    if(typeof privateKeyUri !== "string") {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    // throw error if private key is not a valid key uri
    if(!SerializerChecker.isKeyUri(privateKeyUri, { type: KeyType.PrivateKey })) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    this.getPrivateKey = async () => {
      return await SerializerModule.deserializeKey(privateKeyUri) as PrivateKey;
    };
  }

  /**
	 * Returns the wallet's private key.
	 */
  private getPrivateKey: () => Promise<PrivateKey>;

  /**
	 * Returns the wallet's public key.
	 *
	 * @param raw - flag to return raw key (JSON Web Key)
	 * @returns public key
	 */
  async getPublicKey(): Promise<string>;
  async getPublicKey(config: { raw?: boolean }): Promise<RawKey>;
  async getPublicKey(config: { secure?: boolean }): Promise<PublicKey>;
  async getPublicKey(config?: { raw?: boolean, secure?: boolean }): Promise<string | RawKey | PublicKey> {
    const publicKey: PublicKey = await KeyModule.generatePublicKey({
      privateKey: await this.getPrivateKey()
    });

    if (config?.raw === true) {
      return await KeyModule.exportKey(publicKey);
    }
    
    if (config?.secure === true) {
      return publicKey
    }

    // return public key uri
    return await SerializerModule.serializeKey(publicKey);
  }

  /**
	 * Returns encrypted data. If a public key uri is passed for the key, the data
   * will be encrypted with a shared key that is generated from the wallet's
   * private key and the recipient's public key. Othewise, a passkey will be
   * derived from the key (passphrase) and used for encrypting the data.
	 *
	 * @param key - public key uri or passphrase
	 * @param data - The data to encrypt
	 * @returns encrypted data as a uri
	 */
  async encrypt(key: string, payload: string): Promise<string> {
    if (!key) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_KEY);
    }

    if (!payload) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_PAYLOAD);
    }

    if(typeof key !== "string" || (SerializerChecker.isKeyUri(key) && !SerializerChecker.isKeyUri(key, { type: KeyType.PublicKey }))) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    if(typeof payload !== "string") {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_PAYLOAD);
    }

    let ciphertext: Ciphertext;

    // encrypt with public key if key is a uri or a PublicKey object
    if(SerializerChecker.isKeyUri(key, { type: KeyType.PublicKey })) {
      const recipientPublicKey: PublicKey = await SerializerModule.deserializeKey(key) as PublicKey;

      const publicKey: PublicKey = await this.getPublicKey({ secure: true });
      const sharedKey: SharedKey = await KeyModule.generateSharedKey({ privateKey: await this.getPrivateKey(), publicKey: recipientPublicKey });

      ciphertext = await CryptoModule.encrypt(
        sharedKey,
        payload,
        publicKey,
        recipientPublicKey
      );
    }
    
    // encrypt payload with passphrase
    else if (typeof key === "string") {
      ciphertext = await CryptoModule.encrypt(key, payload);
    }
    
    // throw error (invalid key)
    else {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    // return ciphertext as a uri
    return await SerializerModule.serializeCiphertext(ciphertext);
  }

  /**
	 * Returns decrypted data. If a string is passed for the key, a passkey
	 * will be created from it and used for decrypting the data. Otherwise, the
	 * key must be a Public Key belonging to the sender of the data.
	 *
	 * @param key - public key or passphrase
	 * @param ciphertext - The data to decrypt
	 * @returns decrypted data
	 */
  async decrypt(key: string, ciphertextUri: string): Promise<string> {
    if (!key) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_KEY);
    }

    if (!ciphertextUri) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
    }

    if(typeof key !== "string" || (SerializerChecker.isKeyUri(key) && !SerializerChecker.isKeyUri(key, { type: KeyType.PublicKey }))) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    if(typeof ciphertextUri !== "string") {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    // convert ciphertext string to ciphertext object
    const ciphertext: Ciphertext = await SerializerModule.deserializeCiphertext(
      ciphertextUri
    );

    let plaintext: string;

    if(SerializerChecker.isKeyUri(key, { type: KeyType.PublicKey })) {
      const senderPublicKey: PublicKey = await SerializerModule.deserializeKey(key) as PublicKey;

      const sharedKey = await KeyModule.generateSharedKey({
        privateKey: await this.getPrivateKey(),
        publicKey: senderPublicKey
      });

      plaintext = await CryptoModule.decrypt(sharedKey, ciphertext);
    }

    else if (typeof key === "string") {
      plaintext = await CryptoModule.decrypt(key, ciphertext);
    }

    else {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    return plaintext;
  }

  /**
	 * Returns a ciphertext. The ciphertext contains a digital signature of the message
	 * that is only verifiable by private key belonging to the signer of the message.
	 *
	 * @param message - The message to sign
	 * @returns encrypted signature as a uri
	 */
  async generateSignature(message: string): Promise<string> {
    const encryptedSignature: StandardCiphertext = await CryptoModule.sign(
      await this.getPrivateKey(),
      message
    );

    return await SerializerModule.serializeSignature(encryptedSignature);
  }

  /**
	 * Returns the original message if the signature is valid, otherwise returns null. The
	 * function takes a ciphertext that contains a digital signature of the message. In order
	 * to verify the signature, the wallet instance must contain the private key of the signer.
	 *
	 * @param signatureString - encrypted signature
	 * @returns decrypted signature
	 */
  async verifySignature(signatureUri: string): Promise<string | null> {
    // throw error if signature is missing
    if (!signatureUri) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
    }

    // throw error if signature uri is invalid
    if(!SerializerChecker.isSignatureUri(signatureUri)) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    // deserialize the encrypted signature
    const signature: StandardCiphertext = await SerializerModule.deserializeSignature(signatureUri);

    if (!CryptoChecker.isCiphertext(signature)) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    try {
      return await CryptoModule.verify(await this.getPrivateKey(), signature);
    } catch (error) {
      return null;
    }
  }

  /**
	 * Returns an encrypted challenge (a.k.a. ciphertext) for the claimant to solve.
	 *
	 * @param claimantPublicKeyUri - claimant's public key uri
	 * @param claimantSignatureUri - claimant's signature uri
	 * @returns encrypted challenge as a uri
	 */
  async generateChallenge(claimantPublicKeyUri: string, claimantSignatureUri?: string): Promise<string> {
    // throw error if claimant is missing
    if (!claimantPublicKeyUri) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_KEY);
    }

    // throw error if claimant's public key is invalid
    if(!SerializerChecker.isKeyUri(claimantPublicKeyUri, { type: KeyType.PublicKey })) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    // convert claimant to PublicKey if it is a string
    const claimantPublicKey: PublicKey = await SerializerModule.deserializeKey(claimantPublicKeyUri) as PublicKey;

    // generate a challenge
    const challenge: Challenge = await ChallengeModule.generateChallenge(
      await this.getPrivateKey(),
      claimantPublicKey
    );

    // serialize the challenge
    const challengeUri: string = await SerializerModule.serializeChallenge(challenge);

    // get the wallet's public key
    const publicKey: PublicKey = await this.getPublicKey({ secure: true });

    // generate a shared key
    const sharedKey: SharedKey = await KeyModule.generateSharedKey({
      privateKey: await this.getPrivateKey(),
      publicKey: claimantPublicKey
    });

    // encrypt the challenge with the shared key and return it
    const ciphertext: AdvancedCiphertext = await CryptoModule.encrypt(
      sharedKey,
      challengeUri,
      publicKey,
      claimantPublicKey
    ) as AdvancedCiphertext;

    // convert ciphertext to string
    const ciphertextString: string = await SerializerModule.serializeCiphertext({
      ...ciphertext,
      signature: claimantSignatureUri ? await SerializerModule.deserializeSignature(claimantSignatureUri) : undefined
    });

    return ciphertextString;
  }

  /**
	 * Returns an encrypted challenge-response (a.k.a. solution)
	 *
	 * @param ciphertextUri - encrypted challenge uri
	 * @param config - options object
	 * @param config.requireSignature - whether or not the challenge must have a signature
	 * @returns encrypted challenge-response
	 */
  async generateChallengeResponse(ciphertextUri: string, config?: { requireSignature: boolean }): Promise<string> {
    if (!ciphertextUri) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    const ciphertext: Ciphertext = await SerializerModule.deserializeCiphertext(
      ciphertextUri
    );

    const encryptedChallenge: EncryptedChallenge = _isEncryptedChallenge(ciphertext);

    const publicKey: PublicKey = await this.getPublicKey({ secure: true });

    // throw error if the ciphertext is not meant for this wallet
    const recipientMatchesWallet: boolean = await KeyChecker.isSameKey(
      encryptedChallenge.recipient,
      publicKey
    );

    if (!recipientMatchesWallet) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
    }

    // generate a shared key
    const sharedKey: SharedKey = await KeyModule.generateSharedKey({
      privateKey: await this.getPrivateKey(),
      publicKey: encryptedChallenge.sender
    });

    let challengeString: string;

    // decrypt the challenge
    try {
      challengeString = await CryptoModule.decrypt(
        sharedKey,
        encryptedChallenge
      );
    } catch (error) {
      if ((error as Error).message === CRYPTO_ERROR_MESSAGE.WRONG_KEY) {
        throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
      }

      throw error;
    }

    // deserialize the challenge
    const challenge = await SerializerModule.deserializeChallenge(
      challengeString
    );

    // inspect signature if it is required
    if (config?.requireSignature) {
      // throw error if the ciphertext does not have a signature
      if (encryptedChallenge.signature === undefined) {
        throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE);
      }

      // throw error if the signature is not valid
      if (!CryptoChecker.isCiphertext(encryptedChallenge.signature)) {
        throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE);
      }

      let signedChallenge: Challenge;

      try {
        // encode the ciphertext signature for verification function
        const signatureString = await SerializerModule.serializeSignature(
          encryptedChallenge.signature
        );

        // decrypt/verify the signature
        const challengeString: string | null = await this.verifySignature(
          signatureString
        );

        // throw error if signature does not match this wallet's private key
        if (challengeString === null) {
          throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE);
        }

        // deserialize the encrypted
        signedChallenge = await SerializerModule.deserializeChallenge(
          challengeString
        );
      } catch (error) {
        throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE);
      }

      // throw error if the solution is not meant for this wallet
      const publicKey: PublicKey = await this.getPublicKey({ secure: true });
      const matchesWallet: boolean = await KeyChecker.isSameKey(
        signedChallenge.claimant,
        publicKey
      );
      const matchesVerifier: boolean = await KeyChecker.isSameKey(
        signedChallenge.verifier,
        encryptedChallenge.sender
      );

      if (matchesWallet === false || matchesVerifier === false) {
        throw new Error(WALLET_ERROR_MESSAGE.INVALID_SIGNATURE_ORIGIN);
      }
    }

    // throw error if the challenge is invalid
    if (!ChallengeChecker.isChallenge(challenge)) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
    }

    // throw error if the challenge is not meant for this wallet
    if (!(await KeyChecker.isSameKey(challenge.claimant, publicKey))) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CHALLENGE_ORIGIN);
    }

    // solve the challenge
    const challengeResponse: Challenge = await ChallengeModule.solveChallenge(
      await this.getPrivateKey(),
      challenge
    );

    // serialize the solved challenge
    const challengeResponseUri: string = await SerializerModule.serializeChallenge(
      challengeResponse
    );

    // encrypt the solved challenge with the shared key and return it
    const encryptedChallengeResponse: AdvancedCiphertext = await CryptoModule.encrypt(
      sharedKey,
      challengeResponseUri,
      publicKey,
      encryptedChallenge.sender
    );

    // generate a signature of the solved challenge
    const encryptedSignatureUri = await this.generateSignature(challengeResponseUri);

    // convert ciphertext to uri
    const encryptedChallengeResponseUri = await SerializerModule.serializeCiphertext(
      {
        ...encryptedChallengeResponse,

        // decode encrypted signature and add it to the ciphertext
        signature: await SerializerModule.deserializeSignature(
          encryptedSignatureUri
        )
      }
    );

    return encryptedChallengeResponseUri;
  }

  /**
	 * Returns an object with the claimant's public key and the signature of the solution
	 * if the challenge was solved correctly, otherwise returns null.
	 *
	 * @param ciphertextUri - ciphertext with a challenge-response payload
	 * @returns `{ publicKey, signature? }`
	 */
  async verifyChallengeResponse(ciphertextUri: string): Promise<ChallengeResult | null> {
    if (!ciphertextUri) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    const ciphertext = await SerializerModule.deserializeCiphertext(ciphertextUri);

    const encrypedChallengeResponse: EncryptedChallenge = _isEncryptedChallenge(ciphertext);

    const publicKey: PublicKey = await this.getPublicKey({ secure: true });

    // throw error if ciphertext is not meant for this wallet
    const recipientMatchesWallet = await KeyChecker.isSameKey(
      encrypedChallengeResponse.recipient,
      publicKey
    );

    if (!recipientMatchesWallet) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
    }

    // generate a shared key
    const sharedKey = await KeyModule.generateSharedKey({
      privateKey: await this.getPrivateKey(),
      publicKey: encrypedChallengeResponse.sender
    });

    // decrypt the solution
    let challengeResponse: Challenge

    try {
      const decrypedChallengeResponseString = await CryptoModule.decrypt(
        sharedKey,
        encrypedChallengeResponse
      );

      challengeResponse = await SerializerModule.deserializeChallenge(decrypedChallengeResponseString);
    } catch (error) {
      if (
        (error as Error).message === CRYPTO_ERROR_MESSAGE.INVALID_CIPHERTEXT
      ) {
        throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
      } else if ((error as Error).message === CRYPTO_ERROR_MESSAGE.WRONG_KEY) {
        return null;
      } else {
        throw error;
      }
    }

    const verifierMatchesWallet: boolean = await KeyChecker.isSameKey(
      challengeResponse.verifier,
      publicKey
    );
      
    // throw error if the challenge is not meant for this wallet
    if (!verifierMatchesWallet) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CHALLENGE_ORIGIN);
    }

    // verify the challenge
    const verified: boolean = await ChallengeModule.verifyChallenge(
      await this.getPrivateKey(),
      challengeResponse
    );

    if (!verified) {
      return null;
    }

    return {
      publicKey: await SerializerModule.serializeKey(challengeResponse.claimant),
      signature: encrypedChallengeResponse.signature
        ? await SerializerModule.serializeSignature(encrypedChallengeResponse.signature)
        : undefined
    }
  }
}
