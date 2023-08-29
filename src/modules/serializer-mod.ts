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
}

/**
 * Prefixes for url
 */
export const SerializerPrefix = {
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
  /**
	 * Returns a uri string representation of a key.
   * 
   * The representation has the following format:
   * 
   * `ssasy://key?type=<keyType>&c_kty=<ktyValue>&c_key_ops=<keyOpsValue>&c_alg=<algValue>&c_ext=<extValue>&c_kid=<kidValue>&c_use=<useValue>&c_k=<kValue>&c_crv=<crvValue>&c_x=<xValue>&c_y=<yValue>&c_d=<dValue>&hash=<hashValue>&salt=<saltValue>&iterations=<iterationCount>`
	 *
	 * @param key - key
	 * @returns key
	 * */
  serializeKey: async (key: GenericKey): Promise<string> => {
    
    if (!KeyChecker.isKey(key)) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_KEY);
    }

    const isRawKey: boolean = KeyChecker.isRawKey(key);
    
    const rawKey: RawKey = isRawKey
      ? key as RawKey
      : await KeyModule.exportKey(key);

    let keyString = SerializerPrefix.URI.KEY;

    // add type to keyString
    keyString += `type="${_encodeUriParamValue(rawKey.type)}"`;

    // add domain to keyString
    if(rawKey.domain) {
      keyString += `&domain="${_encodeUriParamValue(rawKey.domain)}"`;
    }

    // add raw flag if key is raw
    if(isRawKey) {
      keyString += `&raw="${_encodeUriParamValue("true")}"`;
    }

    /**
     * Returns a string of RawKey
     */
    function _readProperties(obj: any): string {
      let properties = "";

      for (const [ key, value ] of Object.entries(obj)) {

        if(key === "type" || key === "domain") {
          // skip type and domain
          continue;
        }
        
        if(Array.isArray(value)) {
          // add array to properties
          const arrayValue = `[${value.join(",")}]`
          properties += `&${SerializerPrefix.PARAM.KEY_CRYPTO}${key}="${_encodeUriParamValue(arrayValue)}"`;

        } else if (typeof value === "object") {
          // recursive call if value is an object
          properties += _readProperties(value);

        } else {
          // add property to properties
          properties += `&${SerializerPrefix.PARAM.KEY_CRYPTO}${key}="${_encodeUriParamValue(value as string)}"`;
        }
      }

      return properties;
    }

    keyString += _readProperties(rawKey);


    return keyString
  },
  /**
	 * Returns a key object from a key uri (see `serializeKey`)
	 *
	 * @param key - key uri
	 * @returns key
	 * */
  deserializeKey: async (keyString: string): Promise<GenericKey> => {
    if (!keyString) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_KEY_STRING);
    }

    if(!keyString.startsWith(SerializerPrefix.URI.KEY)){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_KEY_STRING)
    }

    // remove key protocol prefix
    keyString = keyString.slice(SerializerPrefix.URI.KEY.length)

    // extract all properties from key string
    const keyProperties = keyString.split("&");

    /**
     * Returns a RawKey from a key string
     */
    function _rebuildRawKey(keyProperties: string[]): RawKey {
      const rawKey: any = { 
        type: KeyType.Key,
        crypto: {}
      };

      for(let i = 0; i < keyProperties.length; i++){
        // split properties (<key>=<value>)
        const property = keyProperties[i].split("=");
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
    const rawKey: RawKey = _rebuildRawKey(keyProperties);

    // check if raw flag exists
    let isRawKey = false;
    
    if((rawKey as any).raw === "true") {
      // remove raw flag from rawKey
      delete (rawKey as any).raw;
      
      // set isRawKey to true
      isRawKey = true;
    }

    return isRawKey 
      ? rawKey 
      : await KeyModule.importKey(rawKey);
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

    // set nonce
    let challengeString = SerializerPrefix.URI.CHALLENGE;

    // set nonce to challenge string
    challengeString += `nonce="${_encodeUriParamValue(nonce)}"`;
    
    // convert timestamp to string
    const timestampString = timestamp.toString();
    challengeString += `&timestamp="${_encodeUriParamValue(timestampString)}"`;
    
    // convert verifier's public key to string
    let verifierString = await SerializerModule.serializeKey(verifier);
    // replace all double quotes with single quotes
    verifierString = verifierString.replace(/"/g, "'");
    // add verifier to challenge string
    challengeString += `&verifier="${_encodeUriParamValue(verifierString)}"`;
    
    // convert claimant's public key to string
    let claimantString = await SerializerModule.serializeKey(claimant);
    // replace all double quotes with single quotes
    claimantString = claimantString.replace(/"/g, "'");
    // add claimant to challenge string
    challengeString += `&claimant="${_encodeUriParamValue(claimantString)}"`;

    // only include solution if it exists
    if(solution){
      challengeString += `&solution="${_encodeUriParamValue(solution)}"`;
    }

    return challengeString;
  },
  /**
	 * Returns a challenge object from a string representation of a challenge.
	 *
	 * @param challenge - the string representation of the challenge
	 * @returns challenge object
	 * */
  deserializeChallenge: async (challengeString: string): Promise<Challenge> => {
    if(!challengeString) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_CHALLENGE_STRING);
    }

    if(!challengeString.startsWith(SerializerPrefix.URI.CHALLENGE)){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CHALLENGE_STRING)
    }
    
    const challenge = {} as any;
    
    // remove challenge protocol prefix
    challengeString = challengeString.slice(SerializerPrefix.URI.CHALLENGE.length)

    // extract all properties
    const challengeProperties: string[] = challengeString.split("&")
    
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
    for(let i = 0; i < challengeProperties.length; i++){
      const property = challengeProperties[i];
      const key = property.split("=")[0];
      let value = property.split("=")[1];

      // remove quotation marks from value (e.g. key="value")
      value = value.slice(1, value.length - 1)

      // decode property value
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

    let ciphertextString = `${SerializerPrefix.URI.CIPHERTEXT}`;

    // add data to ciphertext string
    ciphertextString += `data="${_encodeUriParamValue(ciphertext.data)}"`;

    // add iv to ciphertext string
    ciphertextString += `&iv="${_encodeUriParamValue(ciphertext.iv)}"`;

    // add salt to ciphertext string (if salt exists)
    if(ciphertext.salt) {
      ciphertextString += `&salt="${_encodeUriParamValue(ciphertext.salt)}"`;
    }

    // add sender to ciphertext string (if sender exists)
    if((ciphertext as AdvancedCiphertext).sender) {
      const sender = (ciphertext as AdvancedCiphertext).sender as PublicKey;
      let senderString = await SerializerModule.serializeKey(sender);

      // replace all double quotes with single quotes
      senderString = senderString.replace(/"/g, "'");

      // add sender to ciphertext string
      ciphertextString += `&sender="${_encodeUriParamValue(senderString)}"`;
    }

    // add recipient to ciphertext string (if recipient exists)
    if((ciphertext as AdvancedCiphertext).recipient) {
      const recipient = (ciphertext as AdvancedCiphertext).recipient as PublicKey;
      let recipientString = await SerializerModule.serializeKey(recipient);

      // replace all double quotes with single quotes
      recipientString = recipientString.replace(/"/g, "'");

      // add recipient to ciphertext string
      ciphertextString += `&recipient="${_encodeUriParamValue(recipientString)}"`;
    }

    // add signature to ciphertext string (if signature exists)
    if((ciphertext as AdvancedCiphertext).signature) {
      const signature = (ciphertext as AdvancedCiphertext).signature as StandardCiphertext;
      let signatureString = await SerializerModule.serializeSignature(signature);

      // replace all double quotes with single quotes
      signatureString = signatureString.replace(/"/g, "'");

      // add signature to ciphertext string
      ciphertextString += `&signature="${_encodeUriParamValue(signatureString)}"`;
    }

    return ciphertextString;
  },
  /**
   * Returns a ciphertext object from a string representation of a ciphertext.
   * 
   * @param ciphertextString - the string representation of the ciphertext
   */
  deserializeCiphertext: async (ciphertextString: string): Promise<Ciphertext> => {
    if(!ciphertextString) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_CIPHERTEXT_STRING);
    }

    if(!ciphertextString.startsWith(SerializerPrefix.URI.CIPHERTEXT)){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_CIPHERTEXT_STRING)
    }

    // remove ciphertext protocol prefix
    ciphertextString = ciphertextString.slice(SerializerPrefix.URI.CIPHERTEXT.length)

    // extract all properties
    const ciphertextProperties: string[] = ciphertextString.split("&")

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
    const ciphertextString = await SerializerModule.serializeCiphertext(signature);
    return ciphertextString.replace(SerializerPrefix.URI.CIPHERTEXT, SerializerPrefix.URI.SIGNATURE);
  },
  /**
   * Returns a signature object from a string representation of a signature.
   * 
   * @param signatureString - the string representation of the signature
   * @returns signature object
   * */
  deserializeSignature: async (signatureString: string): Promise<StandardCiphertext> => {
    if(!signatureString) {
      throw new Error(SERIALIZER_ERROR_MESSAGE.MISSING_SIGNATURE_STRING);
    }

    if(!signatureString.startsWith(SerializerPrefix.URI.SIGNATURE)){
      throw new Error(SERIALIZER_ERROR_MESSAGE.INVALID_SIGNATURE_STRING)
    }

    const ciphertextString = signatureString.replace(SerializerPrefix.URI.SIGNATURE, SerializerPrefix.URI.CIPHERTEXT);
    return await SerializerModule.deserializeCiphertext(ciphertextString);
  }
};
