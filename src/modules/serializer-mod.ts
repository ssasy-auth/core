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
import { KeyChecker, KeyModule } from "./key-mod";
import { ChallengeChecker } from "./challenge-mod";
import { CryptoChecker } from "./crypto-mod";
import type {
  AdvancedCiphertext,
  Challenge,
  Ciphertext,
  GenericKey,
  PublicKey,
  RawKey,
  SecureContextKey,
  StandardCiphertext 
} from "../interfaces";

const SERIALIZER_ERROR_MESSAGE = {
  INVALID_KEY: "Key is invalid or not supported",
  INVALID_KEY_STRING: "Key is invalid",
  
  INVALID_CHALLENGE: "Challenge is invalid",
  INVALID_CHALLENGE_STRING: "Challenge string is invalid",
  
  INVALID_CIPHERTEXT: "Ciphertext is invalid",
  INVALID_CIPHERTEXT_STRING: "Ciphertext string is invalid",
  
  INVALID_SIGNATURE: "Signature is invalid",
  INVALID_SIGNATURE_STRING: "Signature string is invalid",
  
  MISSING_PARAM: "Parameter key or value is missing",
  MISSING_KEY_STRING: "Key is missing",
  MISSING_CHALLENGE_STRING: "Challenge string is missing",
  MISSING_CIPHERTEXT_STRING: "Ciphertext string is missing",
  MISSING_SIGNATURE_STRING: "Signature string is missing",
  
  LEGACY_INVALID_CIPHERTEXT_STRING: "Legacy ciphertext string is invalid",
  LEGACY_INVALID_CHALLENGE_STRING: "Legacy challenge string is invalid" 
};

/**
 * Returns an encoded string for a uri parameter value. The following
 * characters are considered reserved and are encoded: `&`, `,` and `=`.
 */
function _encodeUriParamValue(value: string): string {
  return encodeURIComponent(value)
    .replace(/&/g, "%26")
    .replace(/=/g, "%3D")
    .replace(/'/g, "%27")
    .replace(/"/g, "%22");
}

/**
 * Returns a decoded string for a uri parameter value. The following
 * characters are considered reserved and are decoded: `&`, `,` and `=`.
 */
function _decodeUriParam(value: string): string {
  return decodeURIComponent(value)
    .replace(/%26/g, "&")
    .replace(/%3D/g, "=")
    .replace(/%27/g, "'")
    .replace(/%22/g, "\"");
}

/**
 * Returns a uri parameter from a key-value pair. The parameter is prefixed
 * with an ampersand (`&`) if it is not the first parameter in the uri and
 * the value is encoded.
 * 
 * @param key - parameter key
 * @param value - parameter value
 * @param config - configuration object
 * @param config.first - indicates whether the parameter is the first parameter in the uri
 */
function _constructParam(key: string, value: string, config?: { first?: boolean}): string {
  
  if(!key || !value){
    throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_PARAM);
  }
  
  // encode value
  value = _encodeUriParamValue(value);
  
  return config?.first ? `${key}=${value}` : `&${key}=${value}`;
}

/**
 * Returns key and value from a uri parameter.
 * 
 * @param param - uri parameter
 * @returns key and value
 */
function _deconstructParam(param: string): { key: string, value: string } {
  // get first index of "=" to split property into key and value
  // note: this is a workaround for edge-cases where a value contains "=" (i.e. iv="gjhgdfhshgadhfga==")
  const equalOperatorIndex = param.indexOf("=");
  
  let key: string = param.slice(0, equalOperatorIndex);
  let value: string = param.slice(equalOperatorIndex + 1);

  // remove ampersand from key (e.g. &key=value)
  if(key.startsWith("&")){
    key = key.slice(1);
  }

  // decode property value
  value = _decodeUriParam(value);

  return { key, value };
}

/**
 * ! Temporary fix for legacy resource strings
 */
const LegacySerializerModule = {
  /**
   * Convert legacy key string back to a key object.
   * Old key string format: JSON.stringify(rawKey)
   */
  deserializeKey: (legacyKeyUri: string): RawKey => {
    return JSON.parse(legacyKeyUri);
  },
  /**
   * Converts legacy ciphertext string back to a ciphertext object.
   * Old ciphertext string format: `"{ iv, data, salt?, sender?, recipient?, signature? }"`
   * 
   * @param ciphertextUri - legacy ciphertext string
   * @returns ciphertext object
   * 
   */
  deserializeCiphertext: async (legacyCiphertextUri: string): Promise<Ciphertext> => {
    interface ShallowCiphertext extends Omit<Ciphertext, "sender" | "recipient" | "signature"> {
          sender?: string;
          recipient?: string;
          signature?: string;
        }
        
    const shallowCiphertext: ShallowCiphertext = JSON.parse(legacyCiphertextUri);
        
    const ciphertext = {
      data: shallowCiphertext.data,
      iv: shallowCiphertext.iv 
    } as any;

    if(shallowCiphertext.salt){
      ciphertext.salt = shallowCiphertext.salt;
    }

    if(shallowCiphertext.sender){
      // deserialize stringified key if it is a string (do the same for recipient and signature)
      const key: RawKey = typeof shallowCiphertext.sender === "string"
        ? LegacySerializerModule.deserializeKey(shallowCiphertext.sender)
        : shallowCiphertext.sender as unknown as RawKey;

      ciphertext.sender = await KeyModule.importKey(key) as PublicKey;
    }

    if(shallowCiphertext.recipient){
      const key: RawKey = typeof shallowCiphertext.recipient === "string"
        ? LegacySerializerModule.deserializeKey(shallowCiphertext.recipient)
        : shallowCiphertext.recipient as unknown as RawKey;

      ciphertext.recipient = await KeyModule.importKey(key) as PublicKey;
    }

    if(shallowCiphertext.signature){
      const legacySignature: StandardCiphertext = typeof shallowCiphertext.signature === "string"
        ? await LegacySerializerModule.deserializeCiphertext(shallowCiphertext.signature)
        : shallowCiphertext.signature as unknown as StandardCiphertext;
      
      ciphertext.signature = legacySignature;
    }

    return ciphertext as Ciphertext;
  },
  /**
   * Converts legacy challenge string back to a challenge object.
   * Old challenge string format: `<nonce>::<timestamp>::<raw verifier public key>::<raw claimant public key>::<solution>`
   * 
   * @param legacyChallengeUri - legacy challenge string
   * @returns challenge object
   */
  deserializeChallenge: async (legacyChallengeUri: string): Promise<Challenge> => {
    const properties = legacyChallengeUri.split("::");
    const challenge = {} as any;

    if(properties.length < 4){
      throw new Error("legacy uri is missing required properties (4)");
    }
  
    challenge.nonce = properties[0];
    challenge.timestamp = Number(properties[1]);
    challenge.solution = properties[4];

    const verifier = properties[2];
    const claimant = properties[3];

    const verifierRawPublicKey: RawKey = LegacySerializerModule.deserializeKey(verifier);
    const claimantRawPublicKey: RawKey = LegacySerializerModule.deserializeKey(claimant);

    challenge.verifier = await KeyModule.importKey(verifierRawPublicKey) as PublicKey;
    challenge.claimant = await KeyModule.importKey(claimantRawPublicKey) as PublicKey;
       
    return challenge as Challenge;
  } 
};

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
  PARAM: { KEY_CRYPTO: "c_" } 
};

/**
 * Operations for serializing SSASy resources for transport
 */
const SerializerModule = {
  PREFIX: SerializerPrefix,

  /**
	 * Returns a uri string representation of a key.
   * 
   * The representation has the following format:
   * 
   * `ssasy://key?type=value&domain=value&hash=value&salt=value&iterations=value&c_kty=value&c_key_ops=value&c_alg=value&c_ext=value&c_kid=value&c_use=value&c_k=value&c_crv=value&c_x=value&c_y=value&c_d=value`
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
    keyUri += _constructParam("type", rawKey.type, { first: true });
    
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

      // skip param if it does not exist in raw key or nested crypto object
      if (
        !(rawKey as any)[cleanParam] !== undefined &&
        !(isCryptoValue && (rawKey.crypto as any)[cleanParam] !== undefined)
      ) {
        continue;
      }
      
      // set value depending on whether it belongs to crypto object
      let paramValue: any = isCryptoValue ? (rawKey.crypto as any)[cleanParam] : (rawKey as any)[cleanParam];

      // convert value to a string if it is an array
      if (Array.isArray(paramValue)) {
        paramValue = `[${paramValue.join(",")}]`;
      }

      // add param to keyUri
      keyUri += _constructParam(paramKey, paramValue);
    }

    return keyUri;
  },
  /**
	 * Returns a key object from a key uri (see `serializeKey`)
	 *
	 * @param key - key uri
   * @param config - configuration object
   * @param config.raw - returns a raw key instead of a secure context key
	 * @returns key
	 * */
  deserializeKey: async (keyUri: string, config?: { raw: boolean }): Promise<SecureContextKey | RawKey> => {
    if (!keyUri) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_KEY_STRING);
    }

    if(typeof keyUri !== "string" || !SerializerChecker.isKeyUri(keyUri)){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_KEY_STRING);
    }

    // remove key protocol prefix
    keyUri = keyUri.slice(SerializerPrefix.URI.KEY.length);

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

      for(const param of keyParams){
        const deconstructedParam = _deconstructParam(param);

        let key: string = deconstructedParam.key;
        let value: string | string[] = deconstructedParam.value;

        if(value.startsWith("[") && value.endsWith("]")){
          value = value.slice(1, -1).split(",");
        }
        
        // add value to nested crypto object if key starts with crypto prefix
        if(key.startsWith(SerializerPrefix.PARAM.KEY_CRYPTO)){
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

    return config?.raw 
      ? rawKey 
      : await KeyModule.importKey(rawKey);
  },
  /**
	 * Returns a uri string representation of a challenge.
   * 
   * The representation has the following format:
   * `ssasy://challenge?nonce=value&solution=value&timestamp=value&verifier=value&claimant=value`
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
    challengeUri += _constructParam("nonce", nonce, { first: true });
    
    // convert timestamp to string
    const timestampString = timestamp.toString();
    challengeUri += _constructParam("timestamp", timestampString);
    
    // add verifier
    const verifierUri = await SerializerModule.serializeKey(verifier);
    challengeUri += _constructParam("verifier", verifierUri);
    
    // add claimant
    const claimantUri = await SerializerModule.serializeKey(claimant);
    challengeUri += _constructParam("claimant", claimantUri);

    // add solution (if exists)
    if(solution){
      challengeUri += _constructParam("solution", solution);
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

    if(typeof challengeUri !== "string"){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
    }

    if(!SerializerChecker.isChallengeUri(challengeUri)){
      /**
       * ! Temporary fix for legacy challenge strings
       * 
       * This block needs to handle the edge-case where a challenge uri is
       * conforming to the old format: `<nonce>::<timestamp>::<verifier>::<claimant>::<solution>`
       */

      let migratedLegacyUri = false;
      
      
      try {
        const legacyChallenge: Challenge = await LegacySerializerModule.deserializeChallenge(challengeUri);

        challengeUri = await SerializerModule.serializeChallenge(legacyChallenge);
        
        migratedLegacyUri = true;
        
      } catch (error) {
        throw new Error(SERIALIZER_ERROR_MESSAGE.LEGACY_INVALID_CHALLENGE_STRING);
      }

      if(!migratedLegacyUri){
        throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
      }
    }
    
    /**
     * Returns a typed challenge value based on key string
     */
    async function _getTypedValue(key: string, value: string): Promise<string | number | PublicKey> {
      if(key === "nonce" || key === "solution"){
        return value as string;
      } else if(key === "timestamp"){
        return Number(value) as number;
      } else if(key === "verifier" || key === "claimant"){
        return await SerializerModule.deserializeKey(value) as PublicKey;
      } else {
        throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING);
      }
    }

    async function rebuildChallenge(challengeParams: string[]): Promise<Challenge> {
      const challenge: any = {};

      for(const param of challengeParams){
        const { key, value } = _deconstructParam(param);
        
        // get typed value
        const typedValue = await _getTypedValue(key, value);
        
        challenge[key] = typedValue;
      }

      return challenge as Challenge;
    }
    
    // remove challenge protocol prefix
    challengeUri = challengeUri.slice(SerializerPrefix.URI.CHALLENGE.length);

    // extract all properties
    const challengeParams: string[] = challengeUri.split("&");

    return await rebuildChallenge(challengeParams);
  },
  /**
   * Returns a uri string representation of a ciphertext.
   * 
   * The representation has the following format: 
   * - standard ciphertext: `ssasy://ciphertext?data=value&iv=value&salt=value`
   * - advanced ciphertext: `ssasy://ciphertext?data=value&iv=value&salt=value&sender=value&recipient=value&signature=value`
   * 
   * @param ciphertext - the ciphertext to convert to a string
   */
  serializeCiphertext: async (ciphertext: Ciphertext): Promise<string> => {
    if(!CryptoChecker.isCiphertext(ciphertext)) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT);
    }

    let ciphertextUri = `${SerializerPrefix.URI.CIPHERTEXT}`;

    // add data to ciphertext string
    ciphertextUri += _constructParam("data", ciphertext.data, { first: true });

    // add iv to ciphertext string
    ciphertextUri += _constructParam("iv", ciphertext.iv);

    // add salt to ciphertext string (if salt exists)
    if(ciphertext.salt) {
      ciphertextUri += _constructParam("salt", ciphertext.salt);
    }

    // add sender to ciphertext string (if sender exists)
    if((ciphertext as AdvancedCiphertext).sender) {
      const sender = (ciphertext as AdvancedCiphertext).sender as PublicKey;
      const senderUri = await SerializerModule.serializeKey(sender);

      // add sender to ciphertext string
      ciphertextUri += _constructParam("sender", senderUri);
    }

    // add recipient to ciphertext string (if recipient exists)
    if((ciphertext as AdvancedCiphertext).recipient) {
      const recipient = (ciphertext as AdvancedCiphertext).recipient as PublicKey;
      const recipientUri = await SerializerModule.serializeKey(recipient);

      // add recipient to ciphertext string
      ciphertextUri += _constructParam("recipient", recipientUri);
    }

    // add signature to ciphertext string (if signature exists)
    if((ciphertext as AdvancedCiphertext).signature) {
      const signature = (ciphertext as AdvancedCiphertext).signature as StandardCiphertext;
      const signatureUri = await SerializerModule.serializeSignature(signature);

      // add signature to ciphertext string
      ciphertextUri += _constructParam("signature", signatureUri);
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

    if(typeof ciphertextUri !== "string"){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING);
    }

    if(!SerializerChecker.isCiphertextUri(ciphertextUri)){
      /**
       * ! Temporary fix for legacy challenge strings
       * 
       * This block needs to handle the edge-case where a ciphertext uri is
       * conforming to the old format: `"{ iv, data, salt?, sender?, recipient?, signature? }"`
       */

      let migratedLegacyUri = false;

      try {
        const legacyCiphertext: Ciphertext = await LegacySerializerModule.deserializeCiphertext(ciphertextUri);
        
        ciphertextUri = await SerializerModule.serializeCiphertext(legacyCiphertext);
        migratedLegacyUri = true;
        
      } catch (error) {
        throw new Error(SERIALIZER_ERROR_MESSAGE.LEGACY_INVALID_CIPHERTEXT_STRING);
      }

      if(!migratedLegacyUri){
        throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING);
      }
    }

    /**
     * Returns a typed ciphertext value based on key string
     */
    async function _getTypedValue(key: string, value: string): Promise<string | PublicKey | StandardCiphertext | undefined> {
      if(key === "data" || key === "iv" || key === "salt"){
        return value as string;

      } else if(key === "signature"){
        try {
          return await SerializerModule.deserializeSignature(value) as StandardCiphertext;          
        } catch (error) {
          throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_SIGNATURE_STRING);
        }
      } else if(key === "sender" || key === "recipient"){
        return await SerializerModule.deserializeKey(value) as PublicKey;

      } else {
        throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING);
      }
    }

    async function _rebuildCiphertext(ciphertextParams: string[]): Promise<Ciphertext>{
      const ciphertext: any = {};

      for(const param of ciphertextParams){
        const { key, value } = _deconstructParam(param);
        
        // get typed value
        const typedValue = await _getTypedValue(key, value as string);

        ciphertext[key] = typedValue;
      }

      return ciphertext as Ciphertext;
    }

    // remove ciphertext protocol prefix
    ciphertextUri = ciphertextUri.slice(SerializerPrefix.URI.CIPHERTEXT.length);

    // extract all parameters
    const ciphertextParams: string[] = ciphertextUri.split("&");

    return await _rebuildCiphertext(ciphertextParams);
  },
  /**
   * Returns a uri string representation of a signature.
   * 
   * The representation has the following format:
   * `ssasy://signature?data=value&iv=value`
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
    if(!signatureUri || !SerializerChecker.isSignatureUri(signatureUri)) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_SIGNATURE_STRING);
    }

    const ciphertextUri = signatureUri.replace(SerializerPrefix.URI.SIGNATURE, SerializerPrefix.URI.CIPHERTEXT);
    return await SerializerModule.deserializeCiphertext(ciphertextUri);
  } 
};

/**
 * Returns true if arg has a valid prefix.
 */
function _hasValidPrefix(arg: any, prefix: string): boolean {
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

/**
 * Returns decoded uri params from a uri string.
 */
function _extractUriParams(uri: string, prefix: string): {key: string, value: string}[] {
  // remove protocol prefix
  uri = uri.slice(prefix.length);

  // extract all properties from key string
  const properties: string[] = uri.split("&");

  return properties.map(property => _deconstructParam(property));
}

type KeyT = KeyType.Key | KeyType.SecretKey | KeyType.PassKey | KeyType.PublicKey | KeyType.PrivateKey | KeyType.SharedKey;

const SerializerChecker = {
  /**
   * Returns true if a key uri is valid.
   * 
   * @param keyUri - encoded key uri
   * @param config - configuration object
   * @param config.type - match key type
   * @returns true if key uri is valid
   */
  isKeyUri: (keyUri: string, config?: { type?: KeyT } ): boolean => {
    const requiredParams = [ "type", "c_kty", "c_key_ops", "c_ext" ];
    const requiredSymmetricParams = [ ...requiredParams, "c_alg", "c_k" ];
    const requiredAsymmetricParams = [ ...requiredParams, "c_crv", "c_x", "c_y" ]; // excluding `c_d` (private key)
    
    if(!_hasValidPrefix(keyUri, SerializerPrefix.URI.KEY)) {
      return false;
    }

    const params: {key: string, value: string}[] = _extractUriParams(keyUri, SerializerPrefix.URI.KEY);
    
    
    // arg must have required params
    if(params.length < requiredParams.length) {
      return false;
    }

    const keyType: string | undefined = params.find(param => param.key === "type")?.value;

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

  /**
   * Returns true if a challenge uri is valid.
   * 
   * @param challengeUri - encoded challenge uri
   * @returns true if challenge uri is valid
   */
  isChallengeUri: (challengeUri: string): boolean => {
    const requiredParams = [ "nonce", "timestamp", "verifier", "claimant" ];
    const maxParams = [ ...requiredParams, "solution" ];
    
    if(!_hasValidPrefix(challengeUri, SerializerPrefix.URI.CHALLENGE)) {
      return false;
    }

    const params: {key: string, value: string}[] = _extractUriParams(challengeUri, SerializerPrefix.URI.CHALLENGE);

    // arg must have required params
    if(params.length < requiredParams.length){
      return false;
    }

    // arg should not exceed max params
    if(params.length > maxParams.length){
      return false;
    }

    try {
      const nonce: string | undefined = params.find(param => param.key === "nonce")?.value;
      const timestamp: string | undefined = params.find(param => param.key === "timestamp")?.value;
      const verifier: string | undefined = params.find(param => param.key === "verifier")?.value;
      const claimant: string | undefined = params.find(param => param.key === "claimant")?.value;

      if(
        (!nonce || !timestamp || !verifier || !claimant) || // required params must exist
        !SerializerChecker.isKeyUri(verifier) || // verifier must be a valid key uri
        !SerializerChecker.isKeyUri(claimant) // claimant must be a valid key uri
      ){
        return false;
      }
      
    } catch (error) {
      return false;
    }

    return true;
  },

  isCiphertextUri: (ciphertextUri: string): boolean => {
    const requiredParams = [ "data", "iv" ];
    const maxParamas = [ ...requiredParams, "salt", "sender", "recipient", "signature" ];
    
    if(!_hasValidPrefix(ciphertextUri, SerializerPrefix.URI.CIPHERTEXT)) {
      return false;
    }

    const params: {key: string, value: string}[] = _extractUriParams(ciphertextUri, SerializerPrefix.URI.CIPHERTEXT);
    
    // arg must have required params
    if(params.length < requiredParams.length){
      return false;
    }

    // arg should not exceed max params
    if(params.length > maxParamas.length){
      return false;
    }

    try {
      const data: string | undefined = params.find(param => param.key === "data")?.value;
      const iv: string | undefined = params.find(param => param.key === "iv")?.value;
      const sender: string | undefined = params.find(param => param.key === "sender")?.value;
      const recipient: string | undefined = params.find(param => param.key === "recipient")?.value;
      const signature: string | undefined = params.find(param => param.key === "signature")?.value;

      if(
        (data === "" || data === "undefined") ||
        (iv === "" || iv === "undefined")
      ){
        return false;
      }
  
      if(sender && !SerializerChecker.isKeyUri(sender)){
        return false;
      }
  
      if(recipient && !SerializerChecker.isKeyUri(recipient)){
        return false;
      }
  
      if(signature && !SerializerChecker.isSignatureUri(signature)){
        return false;
      }
    } catch (error) {
      return false;
    }


    return true;
  },

  isSignatureUri: (signatureUri: string): boolean => {
    const requiredParams = [ "data", "iv" ];

    if(!_hasValidPrefix(signatureUri, SerializerPrefix.URI.SIGNATURE)) {
      return false;
    }

    const params: {key: string, value: string}[] = _extractUriParams(signatureUri, SerializerPrefix.URI.SIGNATURE);

    // arg must have required params
    if(params.length < requiredParams.length){
      return false;
    }

    try {
      const data: string | undefined = params.find(param => param.key === "data")?.value;
      const iv: string | undefined = params.find(param => param.key === "iv")?.value;

      if(
        (data === "" || data === "undefined") ||
        (iv === "" || iv === "undefined")
      ){
        return false;
      }
    } catch (error) {
      return false;
    }

    return true;
  } 
};

export {
  SERIALIZER_ERROR_MESSAGE,
  SerializerModule,
  SerializerChecker 
};