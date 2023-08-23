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
  AdvancedCiphertext,
  PrivateKey,
  PublicKey ,
  StandardCiphertext,
  Challenge
} from "./interfaces";

export const WALLET_ERROR_MESSAGE = {
  INVALID_KEY: "The key provided is invalid or not supported by this method",
  INVALID_CONSTRUCTOR_PARAMS: "Key is missing from constructor parameters",
  INVALID_CIPHERTEXT: "The ciphertext is invalid or missing",
  INVALID_CIPHERTEXT_ORIGIN: "The ciphertext sender or recipient does not match the wallet's public key",
  INVALID_CIPHERTEXT_SIGNATURE: "The ciphertext signature is invalid or missing",
  INVALID_CHALLENGE_ORIGIN: "The challenge verifier or claimant does not match the wallet's public key",
  INVALID_SIGNATURE_ORIGIN: "The signature's parties do not match the challenge's parties",
  MISSING_KEY: "Key is missing",
  MISSING_PAYLOAD: "Payload is missing",
  MISSING_CIPHERTEXT_CHALLENGE: "Ciphertext is missing challenge",
  MISSING_CIPHERTEXT_PARTIES: "Ciphertext is missing sender or recipient",
  MISSING_SIGNATURE_MESSAGE: "Signature message is missing"
}

interface AdvancedChallengeCiphertext extends Omit<AdvancedCiphertext, "sender" | "recipient"> {
  sender: PublicKey;
  recipient: PublicKey;
}

/**
 * Returns ciphertext if it contains the correct sender and recipient
 */
function processChallengeCiphertext(ciphertext: unknown): AdvancedChallengeCiphertext {
  if (!ciphertext) {
    throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
  }

  const challengeCiphertext = ciphertext as AdvancedCiphertext;

  if(!challengeCiphertext.sender || !challengeCiphertext.recipient) {
    throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_PARTIES);
  }

  if (!challengeCiphertext.data) {
    throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
  }
  
  if(!CryptoChecker.isCiphertext(challengeCiphertext)){
    throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
  }

  return challengeCiphertext as AdvancedChallengeCiphertext;
}

/**
 * @class Wallet
 * @classdesc Abstracts the key management and cryptographic operations
 * @param {PrivateKey} privateKey - The private key of the wallet
 */
export class Wallet {
  /**
   * Initiates wallet.
   * 
   * @param privateKey - The private key of the wallet
   */
  constructor(privateKey: PrivateKey) {
    const key: PrivateKey = privateKey;

    if(!privateKey) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CONSTRUCTOR_PARAMS);
    }

    if(!KeyChecker.isAsymmetricKey(privateKey) || privateKey.type !== KeyType.PrivateKey) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    this.getPrivateKey = () => key;
  }

  /**
   * Returns the wallet's private key.
   */
  private getPrivateKey: () => PrivateKey;

  /**
   * Returns the wallet's public key.
   * 
   * @returns public key
   */
  async getPublicKey(): Promise<PublicKey> {
    return KeyModule.generatePublicKey({
      privateKey: this.getPrivateKey()
    });
  }

  /**
	 * Returns encrypted data. If a string is passed for the key,a passkey
   * will be created from it and used for encrypting the data. Otherwise,
   * the key must be a Public Key.
	 *
	 * @param key - public key or passphrase
	 * @param data - The data to encrypt
	 */
  async encrypt(key: string, payload: string): Promise<StandardCiphertext>;
  async encrypt(key: PublicKey, payload: string): Promise<AdvancedCiphertext>;
  async encrypt(key: PublicKey | string, payload: string): Promise<Ciphertext> {
    if(!key) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_KEY);
    }

    if(!payload) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_PAYLOAD);
    }

    if(typeof key === "string") {
      
      return await CryptoModule.encrypt(key, payload);
    }

    else if (KeyChecker.isAsymmetricKey(key) && key.type === KeyType.PublicKey) {

      const publicKey = await this.getPublicKey();
      const sharedKey = await KeyModule.generateSharedKey({
        privateKey: this.getPrivateKey(), publicKey: key 
      });
      return await CryptoModule.encrypt(sharedKey, payload, publicKey, key);
    } 

    else {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }
  }

  /**
	 * Returns decrypted data. If a string is passed for the key, a passkey 
   * will be created from it and used for decrypting the data. Otherwise, the 
   * key must be a Public Key.
	 *
	 * @param key - public key or passphrase
	 * @param ciphertext - The data to decrypt
	 */
  async decrypt(key: PublicKey | string, ciphertext: Ciphertext): Promise<string> {
    if(!key) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_KEY);
    }

    if(!ciphertext) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    if(typeof key === "string") {

      return await CryptoModule.decrypt(key, ciphertext);

    } else if (KeyChecker.isAsymmetricKey(key) && key.type === KeyType.PublicKey) {
      
      const sharedKey = await KeyModule.generateSharedKey({
        privateKey: this.getPrivateKey(), publicKey: key 
      });
      return await CryptoModule.decrypt(sharedKey, ciphertext);

    } else {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }
  }

  /**
   * Returns a ciphertext. The ciphertext contains a digital signature of the message
   * that is only verifiable by private key belonging to the signer of the message.
   * 
   * @param message - The message to sign
   * @returns ciphertext signature
   */
  async sign(message: string): Promise<StandardCiphertext> {
    return await CryptoModule.sign(this.getPrivateKey(), message);
  }

  /**
   * Returns the original message if the signature is valid, otherwise returns null. The
   * function takes a ciphertext that contains a digital signature of the message. In order
   * to verify the signature, the wallet instance must contain the private key of the signer.
   * 
   * @param ciphertext - ciphertext signature
   */
  async verify(ciphertext: StandardCiphertext): Promise<string | null> {
    if(!ciphertext) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    if(!CryptoChecker.isCiphertext(ciphertext)) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    try {
      return await CryptoModule.verify(this.getPrivateKey(), ciphertext);
    } catch (error) {
      return null;
    }
  }

  /**
	 * Returns an encrypted challenge.
	 *
	 * @param claimant - The public key of the claimant
	 */
  async generateChallenge(claimant: PublicKey, signature?: StandardCiphertext): Promise<AdvancedCiphertext> {
    if(!claimant) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_KEY);
    }

    if(!KeyChecker.isAsymmetricKey(claimant) || claimant.type !== KeyType.PublicKey) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_KEY);
    }

    // generate a challenge
    const challenge = await ChallengeModule.generateChallenge(this.getPrivateKey(), claimant);
    // encode the challenge
    const encodedChallenge = await EncoderModule.encodeChallenge(challenge);
    // get the wallet's public key
    const publicKey = await this.getPublicKey();
    // generate a shared key
    const sharedKey = await KeyModule.generateSharedKey({
      privateKey: this.getPrivateKey(), publicKey: claimant 
    });
    
    // encrypt the challenge with the shared key and return it
    const ciphertext: AdvancedCiphertext = await CryptoModule.encrypt(sharedKey, encodedChallenge, publicKey, claimant) as AdvancedCiphertext;

    return {
      ...ciphertext,
      signature
    }
  }

  /**
	 * Returns an encrypted solution.
	 *
	 * @param ciphertext - ciphertext with a challenge payload
   * @param config - options object
   * @param config.requireSignature - whether or not the challenge must have a signature
	 */
  async solveChallenge(ciphertext: AdvancedCiphertext, config?: { requireSignature: boolean }): Promise<AdvancedCiphertext> {
    const challengeCiphertext = processChallengeCiphertext(ciphertext);
    
    const publicKey = await this.getPublicKey();

    // throw error if the ciphertext is not meant for this wallet
    const recipientMatchesWallet = await KeyChecker.isSameKey(challengeCiphertext.recipient, publicKey);
    if (!recipientMatchesWallet) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
    }
    
    // generate a shared key
    const sharedKey = await KeyModule.generateSharedKey({
      privateKey: this.getPrivateKey(), publicKey: challengeCiphertext.sender 
    });

    // decrypt the challenge
    let encodedChallenge: string;
    
    try {
      encodedChallenge = await CryptoModule.decrypt(sharedKey, challengeCiphertext);
    } catch (error) {

      if((error as Error).message === CRYPTO_ERROR_MESSAGE.WRONG_KEY){
        throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
      }

      throw error;
    }
    
    // decode the challenge
    const challenge = await EncoderModule.decodeChallenge(encodedChallenge);

    // throw errors if challenge contents don't match signature
    if(config?.requireSignature) {
      // throw error if the ciphertext is not signed
      if(challengeCiphertext.signature === undefined) {
        throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE);
      }

      // throw error if the signature is not valid
      if(!CryptoChecker.isCiphertext(challengeCiphertext.signature)) {
        throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE);
      }

      let solution: Challenge;

      // throw error if signature does not match this wallet's private key
      try {
        const encodedSolution: string | null = await this.verify(challengeCiphertext.signature);

        if(encodedSolution === null) {
          throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE);
        }

        // decode the solution
        solution = await EncoderModule.decodeChallenge(encodedSolution);

      } catch (error) {
        throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_SIGNATURE);
      }

      // throw error if the solution is not meant for this wallet
      const publicKey = await this.getPublicKey();
      const matchesWallet: boolean = await KeyChecker.isSameKey(solution.claimant, publicKey);
      const matchesVerifier: boolean = await KeyChecker.isSameKey(solution.verifier, challengeCiphertext.sender);

      if (matchesWallet === false || matchesVerifier === false) {
        throw new Error(WALLET_ERROR_MESSAGE.INVALID_SIGNATURE_ORIGIN);
      }
    }

    // throw error if the challenge is invalid
    if(!ChallengeChecker.isChallenge(challenge)) {
      throw new Error(WALLET_ERROR_MESSAGE.MISSING_CIPHERTEXT_CHALLENGE);
    }

    // throw error if the challenge is not meant for this wallet
    if(!await KeyChecker.isSameKey(challenge.claimant, publicKey)) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CHALLENGE_ORIGIN);
    }

    // solve the challenge
    const solution: Challenge = await ChallengeModule.solveChallenge(this.getPrivateKey(), challenge);
    
    // encode the solved challenge
    const encodedSolution: string = await EncoderModule.encodeChallenge(solution);

    // encrypt the solved challenge with the shared key and return it
    const solutionCiphertext: AdvancedCiphertext = await CryptoModule.encrypt(sharedKey, encodedSolution, publicKey, challengeCiphertext.sender);

    return {
      ...solutionCiphertext,
      // create a signature of the solved challenge
      signature: await this.sign(encodedSolution)
    };
  }

  /**
	 * Returns an object with the claimant's public key and the signature of the solution
   * if the challenge was solved correctly, otherwise returns null.
	 *
   * @param ciphertext - ciphertext with a challenge payload
   * @returns `{ publicKey, signature? }`
  */
  async verifyChallenge(ciphertext: AdvancedCiphertext): Promise<{ publicKey: PublicKey, signature?: StandardCiphertext } | null> {
    const solutionCiphertext = processChallengeCiphertext(ciphertext);
    
    const publicKey = await this.getPublicKey();

    // throw error if ciphertext is not meant for this wallet
    const recipientMatchesWallet = await KeyChecker.isSameKey(solutionCiphertext.recipient, publicKey);
    if (!recipientMatchesWallet) {
      throw new Error(WALLET_ERROR_MESSAGE.INVALID_CIPHERTEXT_ORIGIN);
    }

    // generate a shared key
    const sharedKey = await KeyModule.generateSharedKey({
      privateKey: this.getPrivateKey(), publicKey: solutionCiphertext.sender 
    });

    // decrypt the solution
    let encodedSolution: string;

    try {
      encodedSolution = await CryptoModule.decrypt(sharedKey, solutionCiphertext);
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
    const verified = await ChallengeModule.verifyChallenge(this.getPrivateKey(), solution);

    const result = {
      publicKey: solution.claimant,
      signature: solutionCiphertext.signature
    }

    return verified
      ? result
      : null;
  }
}
