import { KeyType } from "./interfaces";
import {
  EncoderModule,
  ChallengeModule,
  ChallengeChecker,
  CryptoModule,
  CryptoChecker,
  CRYPTO_ERROR_MESSAGE,
  KeyModule,
  KeyChecker
} from "./modules";
import type {
  Ciphertext,
  PrivateKey,
  PublicKey 
} from "./interfaces";

export const WALLET_ERROR_MESSAGE = {
  INVALID_KEY: "The key provided is invalid or not supported by this method",
  INVALID_CONSTRUCTOR_PARAMS: "Key is missing from constructor parameters",
  INVALID_CIPHERTEXT: "The ciphertext is invalid",
  INVALID_CIPHERTEXT_ORIGIN: "The ciphertext sender or recipient does not match the wallet's public key",
  INVALID_CHALLENGE_ORIGIN: "The challenge verifier or claimant does not match the wallet's public key",
  MISSING_KEY: "Key is missing",
  MISSING_PAYLOAD: "Payload is missing",
  MISSING_CIPHERTEXT: "Ciphertext is missing",
  MISSING_CIPHERTEXT_CHALLENGE: "Ciphertext is missing challenge",
  MISSING_CIPHERTEXT_PARTIES: "Ciphertext is missing sender or recipient"
}

/**
 * @class Wallet
 * @classdesc Abstracts the key management and cryptographic operations
 * @param {PrivateKey} privateKey - The private key of the wallet
 */
export class Wallet {
  private privateKey: PrivateKey;

  /**
   * Creates a new wallet
   * @param privateKey - The private key of the wallet
   */
  constructor(privateKey: PrivateKey) {
    if(!privateKey) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CONSTRUCTOR_PARAMS);
    }

    if(!KeyChecker.isAsymmetricKey(privateKey) || privateKey.type !== KeyType.PrivateKey) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    this.privateKey = privateKey;
  }

  /**
   * Returns the public key of the wallet.
   * 
   * @returns public key
   */
  async getPublicKey(): Promise<PublicKey> {
    return KeyModule.generatePublicKey({
      privateKey: this.privateKey 
    });
  }

  /**
	 * Returns encrypted data using the provided key.
	 *
	 * @param key - public key or passphrase
	 * @param data - The data to encrypt
	 */
  async encrypt(key: PublicKey | string, payload: string): Promise<Ciphertext> {
    if(!key) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_KEY);
    }

    if(!payload) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_PAYLOAD);
    }

    if(typeof key === "string") {
      
      return await CryptoModule.encrypt(key, payload);

    } if (KeyChecker.isAsymmetricKey(key) && key.type === KeyType.PublicKey) {
      
      const publicKey = await this.getPublicKey();
      const sharedKey = await KeyModule.generateSharedKey({
        privateKey: this.privateKey, publicKey: key 
      });
      return await CryptoModule.encrypt(sharedKey, payload, publicKey, key);

    } else {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }
  }

  /**
	 * Returns decrypted data. If a string is passed for the key, a passkey will be created from it and used for
	 * decrypting the data. Otherwise, the key must be a PassKey or SharedKey.
	 *
	 * @param key - public key or passphrase
	 * @param ciphertext - The data to decrypt
	 */
  async decrypt(key: PublicKey | string, ciphertext: Ciphertext): Promise<string> {
    if(!key) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_KEY);
    }

    if(!ciphertext) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
    }

    if(typeof key === "string") {

      return await CryptoModule.decrypt(key, ciphertext);

    } else if (KeyChecker.isAsymmetricKey(key) && key.type === KeyType.PublicKey) {
      
      const sharedKey = await KeyModule.generateSharedKey({
        privateKey: this.privateKey, publicKey: key 
      });
      return await CryptoModule.decrypt(sharedKey, ciphertext);

    } else {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }
  }

  /**
	 * Returns an encrypted challenge
	 *
	 * @param claimant - The public key of the claimant
	 */
  async generateChallenge(claimant: PublicKey): Promise<string> {
    if(!claimant) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_KEY);
    }

    if(!KeyChecker.isAsymmetricKey(claimant) || claimant.type !== KeyType.PublicKey) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    // generate a challenge
    const challenge = await ChallengeModule.generateChallenge(this.privateKey, claimant);
    // encode the challenge
    const encodedChallenge = await EncoderModule.encodeChallenge(challenge);
    // get the wallet's public key
    const publicKey = await this.getPublicKey();
    // generate a shared key
    const sharedKey = await KeyModule.generateSharedKey({
      privateKey: this.privateKey, publicKey: claimant 
    });
    
    // encrypt the challenge with the shared key and return it
    const ciphertext = await CryptoModule.encrypt(sharedKey, encodedChallenge, publicKey, claimant);

    return await EncoderModule.encodeCiphertext(ciphertext);
  }

  /**
	 * Returns an encrypted challenge that has been solved
	 *
	 * @param encodedChallengeCiphertext - a encoded ciphertext of a challenge
	 */
  async solveChallenge(encodedChallengeCiphertext: string): Promise<string> {
    if (!encodedChallengeCiphertext) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
    }

    // decode the ciphertext
    const challengeCiphertext = await EncoderModule.decodeCiphertext(encodedChallengeCiphertext);

    if(!CryptoChecker.isCiphertext(challengeCiphertext)){
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    if(!challengeCiphertext.sender || !challengeCiphertext.recipient) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_PARTIES);
    }
    
    const publicKey = await this.getPublicKey();

    // throw error if the ciphertext is not meant for this wallet
    const recipientMatchesWallet = await KeyChecker.isSameKey(challengeCiphertext.recipient, publicKey);
    if (!recipientMatchesWallet) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
    }
    
    // generate a shared key
    const sharedKey = await KeyModule.generateSharedKey({
      privateKey: this.privateKey, publicKey: challengeCiphertext.sender 
    });

    // decrypt the challenge
    let encodedChallenge: string;
    
    try {
      encodedChallenge = await CryptoModule.decrypt(sharedKey, challengeCiphertext);
    } catch (error) {

      if((error as Error).message === CRYPTO_ERROR_MESSAGE.INVALID_CIPHERTEXT){
        throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
      }

      throw error;
    }
    
    // decode the challenge
    const challenge = await EncoderModule.decodeChallenge(encodedChallenge);

    // throw error if the challenge is invalid
    if(!ChallengeChecker.isChallenge(challenge)) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
    }

    // throw error if the challenge is not meant for this wallet
    if(!await KeyChecker.isSameKey(challenge.claimant, publicKey)) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CHALLENGE_ORIGIN);
    }

    // solve the challenge
    const solution = await ChallengeModule.solveChallenge(this.privateKey, challenge);
    
    // encode the solved challenge
    const encodedSolution = await EncoderModule.encodeChallenge(solution);
    
    // encrypt the solved challenge with the shared key and return it
    const solutionCiphertext = await CryptoModule.encrypt(sharedKey, encodedSolution, publicKey, challengeCiphertext.sender);

    return await EncoderModule.encodeCiphertext(solutionCiphertext);
  }

  /**
	 * Returns claimant's public key if the challenge is solved
	 *
	 * @param encodedSolutionCiphertext - a encoded ciphertext of a challenge
	 */
  async verifyChallenge(encodedSolutionCiphertext: string): Promise<PublicKey | null> {
    if (!encodedSolutionCiphertext) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT);
    }

    // decode the ciphertext
    const decodedSolutionCiphertext = await EncoderModule.decodeCiphertext(encodedSolutionCiphertext);

    if (!decodedSolutionCiphertext.data) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
    }

    if (!decodedSolutionCiphertext.sender || !decodedSolutionCiphertext.recipient) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_PARTIES);
    }

    const publicKey = await this.getPublicKey();

    // throw error if ciphertext is not meant for this wallet
    const recipientMatchesWallet = await KeyChecker.isSameKey(decodedSolutionCiphertext.recipient, publicKey);
    if (!recipientMatchesWallet) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
    }

    // generate a shared key
    const sharedKey = await KeyModule.generateSharedKey({
      privateKey: this.privateKey, publicKey: decodedSolutionCiphertext.sender 
    });

    // decrypt the solution
    let encodedSolution: string;

    try {
      encodedSolution = await CryptoModule.decrypt(sharedKey, decodedSolutionCiphertext);
    } catch (error) {

      if((error as Error).message === CRYPTO_ERROR_MESSAGE.INVALID_CIPHERTEXT){
        throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
      }

      else if ((error as Error).message === CRYPTO_ERROR_MESSAGE.WRONG_KEY) {
        return null;
      }

      else {
        throw error;
      }
    }
    
    const solution = await EncoderModule.decodeChallenge(encodedSolution);
    
    // throw error if the challenge is not meant for this wallet
    const verifierMatchesWallet = await KeyChecker.isSameKey(solution.verifier, publicKey);
    if (!verifierMatchesWallet) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CHALLENGE_ORIGIN);
    }

    // verify the challenge
    const verified = await ChallengeModule.verifyChallenge(this.privateKey, solution);

    return verified
      ? solution.claimant
      : null;
  }
}
