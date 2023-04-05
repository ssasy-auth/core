# `ssasy` logic view

## utils

The utils folder contains the wrappers for the [WebCrypto API](../technology/cryptography.md#webcrypto-api) and the [buffer library](../technology/cryptography.md#buffer-library). These wrappers act as a layer of abstraction between the project and the underlying dependencies which allows the project to be more flexible, in the future, if the underlying dependencies were to change.

The abstraction also allows the project to swap out the underlying dependencies depending on the environment (e.g. browser vs node) which is necessary, for the WebCrypto API.

## modules

The modules folder contains the core logic of the project. This includes key management, cryptographic operations and encoding/decoding operations. The rest of this section will describe the modules in more detail.

### key-mod

Cryptographic keys are used for a number of operations in this project. This includes deriving other keys, encrypting and decrypting payloads, signing and verifying signatures, etc. The `key-mod.ts` is responsible for generating and managing cryptographic keys.

Key generation can lead to four types of keys (see [key docs](./crypto-keys.md) for more details):

1. `SecretKey` - a symmetric key that is used for encrypting and decrypting messages
2. `PassKey` - a symmetric key that is derived from a passphrase (string) and is used for encrypting and decrypting messages
3. `PrivateKey` & `PublicKey` - a pair of asymmetric keys that are used for deriving a `SharedKey` and for signing and verifying signatures
4. `SharedKey` - a symmetric key that is derived from a `PrivateKey` and a `PublicKey` and is used for encrypting and decrypting messages between two parties in a 'asymmetric' way.

Apart from the key generation, the `key-mod.ts` module is also responsible for exporting and importing keys to and from the [JSON Web Key (JWK)](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#json_web_key) format for storage and/or transmission.

The JWK format is used because JSON is ideal for web applications and the JWK format is a standardised format for storing cryptographic keys that supports all the algorithms used in this application. This is not the case for the [RAW](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#raw), [PKCS](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#json_web_key) or [SubjectPublicKeyInfo](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#subjectpublickeyinfo) formats.

> Note: this is the only module that does not depend on other modules.

### crypto-mod

The `crypto-mod.ts` is responsible for all cryptographic operations that are not key management related. This includes:

- generating random numbers (nonces) that are used for generating challenges
- encrypting and decrypting messages with symmetric keys
- hashing messages
- signing and verifying signatures

It is worth noting that the process of signing and verifying signatures is not as straightforward as the documentation suggests. This is because the WebCrypto API for signing and verifying signatures requires `['sign', 'verify']` as the `usages` parameter when importing a key. However, the algorithm that is used to generate the `asymmetric` key pair (ECDH) does not support signing and verifying signatures. For this, you need to use the Elliptic Curve Digital Signature Algorithm (ECDSA) algorithm which is used to generate the `asymmetric` key pair that support signing and verifying signatures.

The reason why there is no single Elliptic Curve algorithm that supports both, encryption/decryption and signing/verifying is that the two algorithms prioritise different performance metrics for the same level of security.

In order to get around this, signing of messages is done by generating a `SharedKey` from the `PrivateKey` and the `PublicKey` of the same key pair. This `SharedKey` is then used to encrypt the message which generates a 'signature'. In order to verify the signature, the same process is followed but in reverse. The message is decrypted using the `SharedKey` and the result is compared to the original message.

### challenge-mod

The `challenge-mod.ts` is responsible for generating and verifying challenges. Challenges are a way for ensuring that someone is in possession of a `PrivateKey` associated with a `PublicKey`.

Assume that a verifier (Alice) wants to check that a claimant (Bob) is in possession of the `PrivateKey` associated with the `PublicKey` that the claimant has provided. The challenge-response ritual is as follows:

1. Alice generates a random number (nonce)
2. Alice generates a shared key from her `PrivateKey` and Bob's `PublicKey`
3. Alice encrypts the nonce using the shared key
4. Alice sends the encrypted nonce to Bob
5. Bob generates a shared key from his `PrivateKey` and Alice's `PublicKey`
6. Bob decrypts the encrypted nonce using the shared key
7. Bob returns some message that includes the decrypted nonce
8. Alice verifies that the decrypted nonce is the same as the original nonce

Although this is a simple example, it plays a critical role in the registration and login processes.

### encoder-mod

The `encoder-mod.ts` is responsible for encoding and decoding data. This is necessary because the WebCrypto API only works with buffers which means that the data is converted to a buffer when in-use and then converted back to a string when it is no longer in-use. This facilitates the storage and transmission of cryptographic resources (e.g. keys, encrypted data, etc.).

At a lower leve, the `encoder-mod.ts` module is responsible for converting data from `Uint8Array` to `base64url` and vice versa. This is necessary because the WebCrypto API primarily works with `Uint8Array` buffers which are not human-readable or suitable for storage and transmission.

## wallet

The `wallet` class provides a a usable interface for the modules by abstracting the underlying modules and providing a more usable and secure interface for developers to use. This is the recommended way for developers to use the library however, the modules can be used directly if necessary.

In order to initialise the `wallet` class, a `PrivateKey` is required. It is important to not that the `wallet` instance does not expose the `PrivateKey` directly since it is defined as a private variable. This is done to prevent developers from accidentally exposing the `PrivateKey` which would compromise the security of the application.

This does not mean that there are no security concerns with the `wallet` instance. For example, an instance can still be used to create signatures, solve challenges, etc. However, the `wallet` instance is designed to be used in a way that minimises the risk of exposing the `PrivateKey`.

The most notable functions in the `wallet` class are:

- `generateChallenge()` - generates an encrypted challenge using the wallet's `PrivateKey` and the `PublicKey` of the recipient
- `solveChallenge()` - solves an encrypted challenge using the wallet's `PrivateKey` and the `PublicKey` of the sender
- `verifyChallenge()` - verifies that a solved challenge is correct using the wallet's `PrivateKey` and the `PublicKey` of the sender
