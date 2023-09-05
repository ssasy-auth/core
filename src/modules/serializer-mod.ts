/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Serializer Module
 * 
 * This module provides functions for serializing and deserializing SSASy 
 * resources (i.e. keys, challenges, ciphertexts and signatures) for transport. 
 * In other words, it provides functions for converting SSASy resources into 
 * URI strings and vice versa.
 */

import { KeyType } from "../interfaces";
import { KeyModule, KeyChecker } from "./key-mod";
import { ChallengeChecker } from "./challenge-mod";
import { CryptoChecker } from "./crypto-mod";
import type {
  PublicKey,
  RawKey,
  GenericKey,
  Challenge,
  Ciphertext,
  StandardCiphertext,
  AdvancedCiphertext
} from "../interfaces";

export const SERIALIZER_ERROR_MESSAGE = {
  INVALID_KEY: "Key is invalid or not supported",
  INVALID_KEY_STRING: "Key is invalid",
  INVALID_CHALLENGE: "Challenge is invalid",
  INVALID_CHALLENGE_STRING: "Challenge string is invalid",
  INVALID_CIPHERTEXT: "Ciphertext is invalid",
  INVALID_CIPHERTEXT_STRING: "Ciphertext string is invalid",
  INVALID_SIGNATURE: "Signature is invalid",
  INVALID_SIGNATURE_STRING: "Signature string is invalid",
  MISSING_KEY_STRING: "Key is missing",
  MISSING_CHALLENGE_STRING: "Challenge string is missing",
  MISSING_CIPHERTEXT_STRING: "Ciphertext string is missing",
  MISSING_SIGNATURE_STRING: "Signature string is missing"
};

/**
 * Returns an encoded string for a uri parameter value. The following
 * characters are considered reserved and are encoded: `&`, `,` and `=`.
 */
function _encodeUriParamValue(value: string): string {
  return encodeURIComponent(value)
    .replace(/&/g, "%26")
    .replace(/,/g, "%2C")
    .replace(/=/g, "%3D")
    .replace(/'/g, "%27")
    .replace(/"/g, "%22")
}

/**
 * Returns a decoded string for a uri parameter value. The following
 * characters are considered reserved and are decoded: `&`, `,` and `=`.
 */
function _decodeUriParam(value: string): string {
  return decodeURIComponent(value)
    .replace(/%26/g, "&")
    .replace(/%2C/g, ",")
    .replace(/%3D/g, "=")
    .replace(/%27/g, "'")
    .replace(/%22/g, "\"")
}

/**
 * Prefixes for uri
 */
const SerializerPrefix = {
  URI: {
    KEY: "ssasy://key?",
    CHALLENGE: "ssasy://challenge?",
    CIPHERTEXT: "ssasy://ciphertext?",
    SIGNATURE: "ssasy://signature?"
  },
  PARAM: {
    KEY_CRYPTO: "c_"
  }
}

/**
 * Operations for serializing SSASy resources for transport
 */
export const SerializerModule = {
  PREFIX: SerializerPrefix,

  /**
	 * Returns a uri string representation of a key.
   * 
   * The representation has the following format:
   * 
   * `ssasy://key?type=<value>&domain=<value>&hash=<value>&salt=<value>&iterations=<value>&c_kty=<value>&c_key_ops=<value>&c_alg=<value>&c_ext=<value>&c_kid=<value>&c_use=<value>&c_k=<value>&c_crv=<value>&c_x=<value>&c_y=<value>&c_d=<value>`
	 *
   * Note: Try to keep the order of the parameters as shown above so that keys that are saved
   * in a database can be easily compared.
   * 
	 * @param key - key
	 * @returns key
	 * */
  serializeKey: async (key: GenericKey): Promise<string> => {
    if (!KeyChecker.isKey(key)) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_KEY);
    }

    const rawKey: RawKey = KeyChecker.isRawKey(key)
      ? key as RawKey
      : await KeyModule.exportKey(key);
    
    let keyUri: string = SerializerPrefix.URI.KEY;

    // add type to keyUri
    keyUri += `type="${_encodeUriParamValue(rawKey.type)}"`;
    
    //! the order of the parameters is important for the key comparison (i.e. database queries)
    const paramKeys: string[] = [
      "domain",
      "hash",
      "salt",
      "iterations",
      `${SerializerPrefix.PARAM.KEY_CRYPTO}kty`,
      `${SerializerPrefix.PARAM.KEY_CRYPTO}key_ops`,
      `${SerializerPrefix.PARAM.KEY_CRYPTO}alg`,
      `${SerializerPrefix.PARAM.KEY_CRYPTO}ext`,
      `${SerializerPrefix.PARAM.KEY_CRYPTO}kid`,
      `${SerializerPrefix.PARAM.KEY_CRYPTO}use`,
      `${SerializerPrefix.PARAM.KEY_CRYPTO}k`,
      `${SerializerPrefix.PARAM.KEY_CRYPTO}crv`,
      `${SerializerPrefix.PARAM.KEY_CRYPTO}x`,
      `${SerializerPrefix.PARAM.KEY_CRYPTO}y`,
      `${SerializerPrefix.PARAM.KEY_CRYPTO}d`
    ];

    for (const paramKey of paramKeys) {
      // check if param belongs to crypto object
      const isCryptoValue: boolean = paramKey.startsWith(SerializerPrefix.PARAM.KEY_CRYPTO);
      
      // remove protocol prefix
      const cleanParam: string = isCryptoValue ? paramKey.slice(SerializerPrefix.PARAM.KEY_CRYPTO.length) : paramKey;

      // skip param if it does not exist
      const inRawKey = (rawKey as any)[cleanParam] !== undefined;
      const inCrypto: boolean = isCryptoValue && (rawKey.crypto as any)[cleanParam] !== undefined;
      if (!inRawKey && !inCrypto) {
        continue;
      }
      
      // set value depending on whether it belongs to crypto object
      let paramValue: any = isCryptoValue ? (rawKey.crypto as any)[cleanParam] : (rawKey as any)[cleanParam];

      // convert value to a string if it is an array
      if (Array.isArray(paramValue)) {
        paramValue = `[${paramValue.join(",")}]`;
      }

      // add param to keyUri
      keyUri += `&${paramKey}="${_encodeUriParamValue(paramValue)}"`;
    }

    return keyUri
  },
  /**
	 * Returns a key object from a key uri (see `serializeKey`)
	 *
	 * @param key - key uri
	 * @returns key
	 * */
  deserializeKey: async (keyUri: string): Promise<GenericKey> => {
    if (!keyUri) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_KEY_STRING);
    }

    if(typeof keyUri !== "string" || !keyUri.startsWith(SerializerPrefix.URI.KEY)){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_KEY_STRING)
    }

    // remove key protocol prefix
    keyUri = keyUri.slice(SerializerPrefix.URI.KEY.length)

    // extract all properties from key string
    const keyParams: string[] = keyUri.split("&");

    /**
     * Returns a RawKey from a key uri
     */
    function _rebuildRawKey(keyParams: string[]): RawKey {
      const rawKey: any = { 
        type: KeyType.Key,
        crypto: {}
      };

      for(let i = 0; i < keyParams.length; i++){
        // split properties (<key>=<value>)
        const property = keyParams[i].split("=");
        let key: string = property[0];
        let value: string | string[] = property[1];

        // remove quotation marks from value (e.g. key="value")
        value = value.slice(1, value.length - 1)

        // decode property value
        value = _decodeUriParam(value)

        // if value starts with `[` and ends with `]`, it was an array
        if(value.startsWith("[") && value.endsWith("]")){
          
          // remove square bracket
          value = value.slice(1, value.length-1)

          //convert value into array
          value = value.split(",");
        }

        // if key starts with `SerializerPrefix.PARAM.KEY_CRYPTO`, it belongs to nested crypto object
        if(key.startsWith(SerializerPrefix.PARAM.KEY_CRYPTO)){
          
          // remove protocol prefix
          key = key.slice(SerializerPrefix.PARAM.KEY_CRYPTO.length);
          
          rawKey.crypto[key] = value;
        } else {
          rawKey[key] = value;
        }
      }

      return rawKey as RawKey;
    }

    // convert raw key to a key instance (secure context)
    const rawKey: RawKey = _rebuildRawKey(keyParams);

    // convert raw key to key instance (secure context) and return
    return await KeyModule.importKey(rawKey);
  },
  /**
	 * Returns a uri string representation of a challenge.
   * 
   * The representation has the following format:
   * `ssasy://challenge?nonce=<nonceValue>&solution=<solutionValue>&timestamp=<timestampValue>&verifier=<verifierPK>&claimant=<claimantPK>`
	 *
	 * @param challenge - the challenge to convert to a string
	 * @returns challenge in string format
	 * */
  serializeChallenge: async (challenge: Challenge): Promise<string> => {
    if (!ChallengeChecker.isChallenge(challenge)) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CHALLENGE);
    }

    const { nonce, timestamp, verifier, claimant, solution } = challenge;

    let challengeUri = SerializerPrefix.URI.CHALLENGE;

    // add nonce
    challengeUri += `nonce="${_encodeUriParamValue(nonce)}"`;
    
    // convert timestamp to string
    const timestampString = timestamp.toString();
    challengeUri += `&timestamp="${_encodeUriParamValue(timestampString)}"`;
    
    // add verifier
    const verifierUri = await SerializerModule.serializeKey(verifier);
    challengeUri += `&verifier="${_encodeUriParamValue(verifierUri)}"`;
    
    // add claimant
    const claimantUri = await SerializerModule.serializeKey(claimant);
    challengeUri += `&claimant="${_encodeUriParamValue(claimantUri)}"`;

    // add solution (if exists)
    if(solution){
      challengeUri += `&solution="${_encodeUriParamValue(solution)}"`;
    }

    return challengeUri;
  },
  /**
	 * Returns a challenge object from a string representation of a challenge.
	 *
	 * @param challengeUri - the string representation of the challenge
	 * @returns challenge object
	 * */
  deserializeChallenge: async (challengeUri: string): Promise<Challenge> => {
    if(!challengeUri) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_CHALLENGE_STRING);
    }

    if(typeof challengeUri !== "string" || !challengeUri.startsWith(SerializerPrefix.URI.CHALLENGE)){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING)
    }
    
    const challenge = {} as any;
    
    // remove challenge protocol prefix
    challengeUri = challengeUri.slice(SerializerPrefix.URI.CHALLENGE.length)

    // extract all properties
    const challengeParams: string[] = challengeUri.split("&")
    
    /**
     * Returns a typed challenge value based on key string
     */
    async function _getTypedValue(key: string, value: string): Promise<string | number | PublicKey> {
      try {
        if(key === "nonce" || key === "solution"){
          return value as string;
        } else if(key === "timestamp"){
          return Number(value) as number
        } else if(key === "verifier" || key === "claimant"){
          return await SerializerModule.deserializeKey(value) as PublicKey;
        } else {
          throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING)
        }
      } catch (error) {
        throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING)
      }
    }
    
    // rebuild challenge object
    for(let i = 0; i < challengeParams.length; i++){
      const param = challengeParams[i];
      const key = param.split("=")[0];
      let value = param.split("=")[1];

      // remove quotation marks from value (e.g. key="value")
      value = value.slice(1, value.length - 1)

      // decode param value
      value = _decodeUriParam(value)

      // get typed value
      const typedValue = await _getTypedValue(key, value);
      
      challenge[key] = typedValue;
    }

    return challenge as Challenge;
  },
  /**
   * Returns a uri string representation of a ciphertext.
   * 
   * The representation has the following format: 
   * - standard ciphertext: `ssasy://ciphertext?data=<dataValue>&iv=<ivValue>&salt=<saltValue>`
   * - advanced ciphertext: `ssasy://ciphertext?data=<dataValue>&iv=<ivValue>&salt=<saltValue>&sender=<senderPK>&recipient=<recipientPK>&signature=<signature>`
   * 
   * @param ciphertext - the ciphertext to convert to a string
   */
  serializeCiphertext: async (ciphertext: Ciphertext): Promise<string> => {
    if(!CryptoChecker.isCiphertext(ciphertext)) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    let ciphertextUri = `${SerializerPrefix.URI.CIPHERTEXT}`;

    // add data to ciphertext string
    ciphertextUri += `data="${_encodeUriParamValue(ciphertext.data)}"`;

    // add iv to ciphertext string
    ciphertextUri += `&iv="${_encodeUriParamValue(ciphertext.iv)}"`;

    // add salt to ciphertext string (if salt exists)
    if(ciphertext.salt) {
      ciphertextUri += `&salt="${_encodeUriParamValue(ciphertext.salt)}"`;
    }

    // add sender to ciphertext string (if sender exists)
    if((ciphertext as AdvancedCiphertext).sender) {
      const sender = (ciphertext as AdvancedCiphertext).sender as PublicKey;
      const senderUri = await SerializerModule.serializeKey(sender);

      // add sender to ciphertext string
      ciphertextUri += `&sender="${_encodeUriParamValue(senderUri)}"`;
    }

    // add recipient to ciphertext string (if recipient exists)
    if((ciphertext as AdvancedCiphertext).recipient) {
      const recipient = (ciphertext as AdvancedCiphertext).recipient as PublicKey;
      const recipientUri = await SerializerModule.serializeKey(recipient);

      // add recipient to ciphertext string
      ciphertextUri += `&recipient="${_encodeUriParamValue(recipientUri)}"`;
    }

    // add signature to ciphertext string (if signature exists)
    if((ciphertext as AdvancedCiphertext).signature) {
      const signature = (ciphertext as AdvancedCiphertext).signature as StandardCiphertext;
      const signatureUri = await SerializerModule.serializeSignature(signature);

      // add signature to ciphertext string
      ciphertextUri += `&signature="${_encodeUriParamValue(signatureUri)}"`;
    }

    return ciphertextUri;
  },
  /**
   * Returns a ciphertext object from a string representation of a ciphertext.
   * 
   * @param ciphertextUri - the string representation of the ciphertext
   */
  deserializeCiphertext: async (ciphertextUri: string): Promise<Ciphertext> => {
    if(!ciphertextUri) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_CIPHERTEXT_STRING);
    }

    if(typeof ciphertextUri !== "string" || !ciphertextUri.startsWith(SerializerPrefix.URI.CIPHERTEXT)){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING)
    }

    // remove ciphertext protocol prefix
    ciphertextUri = ciphertextUri.slice(SerializerPrefix.URI.CIPHERTEXT.length)

    // extract all properties
    const ciphertextProperties: string[] = ciphertextUri.split("&")

    /**
     * Returns a typed ciphertext value based on key string
     */
    async function _getTypedValue(key: string, value: string): Promise<string | PublicKey | StandardCiphertext | undefined> {
      try {
        if(key === "data" || key === "iv" || key === "salt"){
          return value as string;

        } else if(key === "signature"){
          return await SerializerModule.deserializeSignature(value) as StandardCiphertext;

        } else if(key === "sender" || key === "recipient"){
          return await SerializerModule.deserializeKey(value) as PublicKey;

        } else {
          throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING)
        }
      } catch (error) {
        throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING)
      }
    }

    // rebuild ciphertext object
    const ciphertext: any = {};

    for(let i = 0; i < ciphertextProperties.length; i++){
      // get first index of "=" to split property into key and value
      // note: this is a workaround for the case that the value contains "=" (i.e. iv="gjhgdfhshgadhfga==")
      const equalOperatorIndex = ciphertextProperties[i].indexOf("=");
      
      // split properties (<key>=<value>)
      const key = ciphertextProperties[i].slice(0, equalOperatorIndex);
      let value = ciphertextProperties[i].slice(equalOperatorIndex + 1);

      // remove quotation marks from value (e.g. key="value")
      value = value.slice(1, value.length - 1)

      // decode property value
      value = _decodeUriParam(value)

      // get typed value
      const typedValue = await _getTypedValue(key, value);

      ciphertext[key] = typedValue;
    }

    return ciphertext as Ciphertext;
  },
  /**
   * Returns a uri string representation of a signature.
   * 
   * The representation has the following format:
   * `ssasy://signature?data=<dataValue>&iv=<ivValue>`
   * 
   * @param signature - the signature to convert to a string
   */
  serializeSignature: async (signature: StandardCiphertext): Promise<string> => {
    const ciphertextUri = await SerializerModule.serializeCiphertext(signature);
    return ciphertextUri.replace(SerializerPrefix.URI.CIPHERTEXT, SerializerPrefix.URI.SIGNATURE);
  },
  /**
   * Returns a signature object from a string representation of a signature.
   * 
   * @param signatureUri - the string representation of the signature
   * @returns signature object
   * */
  deserializeSignature: async (signatureUri: string): Promise<StandardCiphertext> => {
    if(!signatureUri) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_SIGNATURE_STRING);
    }

    if(!signatureUri.startsWith(SerializerPrefix.URI.SIGNATURE)){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_SIGNATURE_STRING)
    }

    const ciphertextUri = signatureUri.replace(SerializerPrefix.URI.SIGNATURE, SerializerPrefix.URI.CIPHERTEXT);
    return await SerializerModule.deserializeCiphertext(ciphertextUri);
  }
};

function _validCheckerArg(arg: any, prefix: string): boolean {
  if(!arg) {
    return false;
  }

  if(typeof arg !== "string") {
    return false;
  }

  if(!arg.startsWith(prefix)) {
    return false;
  }

  return true;
}

function _extractUriParams(uri: string, prefix: string): string[] {
  // remove protocol prefix
  uri = uri.slice(prefix.length)

  // extract all properties from key string
  const properties = uri.split("&");

  return properties;
}

type KeyT = KeyType.Key | KeyType.SecretKey | KeyType.PassKey | KeyType.PublicKey | KeyType.PrivateKey | KeyType.SharedKey;

export const SerializerChecker = {
  isKeyUri: (keyUri: string, config?: { type?: KeyT } ): boolean => {
    const requiredParams = [ "type", "c_kty", "c_key_ops", "c_ext" ];
    const requiredSymmetricParams = [ ...requiredParams, "c_alg", "c_k" ];
    const requiredAsymmetricParams = [ ...requiredParams, "c_crv", "c_x", "c_y" ]; // excluding `c_d` (private key)
    
    if(!_validCheckerArg(keyUri, SerializerPrefix.URI.KEY)) {
      return false;
    }

    const params = _extractUriParams(keyUri, SerializerPrefix.URI.KEY);
    
    
    // arg must have required params
    if(params.length < requiredParams.length) {
      return false;
    }

    let keyType: string = params.find(param => param.startsWith("type="))?.split("=")[1] || "";

    // remove quotation marks from value (e.g. key="value")
    keyType = keyType.slice(1, keyType.length - 1)

    // key type must match `type`, if it is provided
    if(config?.type && keyType !== config?.type) {
      return false;
    }

    // arg must have asymmetric params if type is asymmetric
    if(
      (keyType === KeyType.PublicKey || keyType === KeyType.PrivateKey) &&
      params.length < requiredAsymmetricParams.length
    ) {
      return false;
    }

    // arg must have symmetric params if type is symmetric
    if(
      (keyType === KeyType.SecretKey || keyType === KeyType.PassKey || keyType === KeyType.SharedKey) &&
      params.length < requiredSymmetricParams.length
    ) {
      return false;
    }

    return true;
  },

  isChallengeUri: (challengeUri: string): boolean => {
    const requiredParams = [ "nonce", "timestamp", "verifier", "claimant" ];
    const maxParams = [ ...requiredParams, "solution" ];
    
    if(!_validCheckerArg(challengeUri, SerializerPrefix.URI.CHALLENGE)) {
      return false;
    }

    const params: string[] = _extractUriParams(challengeUri, SerializerPrefix.URI.CHALLENGE);

    // arg must have required params
    if(params.length < requiredParams.length){
      return false;
    }

    // arg should not exceed max params
    if(params.length > maxParams.length){
      return false;
    }

    return true;
  },

  isCiphertextUri: (ciphertextUri: string): boolean => {
    const requiredParams = [ "data", "iv" ];
    const maxParamas = [ ...requiredParams, "salt", "sender", "recipient", "signature" ];
    
    if(!_validCheckerArg(ciphertextUri, SerializerPrefix.URI.CIPHERTEXT)) {
      return false;
    }

    const params: string[] = _extractUriParams(ciphertextUri, SerializerPrefix.URI.CIPHERTEXT);
    
    // arg must have required params
    if(params.length < requiredParams.length){
      return false;
    }

    // arg should not exceed max params
    if(params.length > maxParamas.length){
      return false;
    }

    return true;
  },

  isSignatureUri: (signatureUri: string): boolean => {
    const requiredParams = [ "data", "iv" ];

    if(!_validCheckerArg(signatureUri, SerializerPrefix.URI.SIGNATURE)) {
      return false;
    }

    const params: string[] = _extractUriParams(signatureUri, SerializerPrefix.URI.SIGNATURE);

    // arg must have required params
    if(params.length < requiredParams.length){
      return false;
    }

    return true;
  }
}