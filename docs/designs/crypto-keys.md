# `ssasy` key generation

Cryptographic keys can be used for a number of reasons. This includes deriving other keys, encrypting and decrypting payloads, signing and verifying signatures, etc.

The type of action that a key can perform is usually dependent on whether the key is `symmetric` or `asymmetric`.

## Symmetric keys

A `symmetric` key is a single key that is used for all cyrptographic operations (encryption, decryption etc.). It is also noteworthy to mention that the `symmetric` came before the `asymmetric` key.

## Asymmetric key pair

An `asymmetric` key pair consists of two mathemtatically related keys that perform different steps in a cryptographic operation. The two keys are usually referred to as the `public` and `private` keys because one key is made public and the other key is kept private.

The way that `asymmetric` keys work is that if one key is used to encrypt a payload, the other key is used to decrypt the payload. This is also true for signing and verifying signatures.

## Symmetric vs Asymmetric keys

At a high level, `symmetric` and `asymmetric` keys tackle two different problems. The main difference is that `symmetric` keys are used to encrypt and decrypt payloads and `asymmetric` keys are used to prove 'identities' and securly exchange `symmetric` keys.

In order to understand the difference between the two types of keys, let's look at an example. Imagine that Alice want to send a message to Bob but she don't want anyone else to be able to read it.

In the 'old days', this process would look something like this:

1. Alice generate a `symmetric` key
2. Alice finds a way to send the symmetric key to Bob without anyone else capturing it
3. Alice writes a message and encrypts it using the symmetric key
4. Alice sends the encrypted message to Bob. It doesn't matter if anyone else captures the message because it is encrypted using the symmetric key.
5. Bob receives the message and decrypts it using the symmetric key

This process gets the job done but it has one **major problem**. If anyone were to capture the symmetric key while it was being sent to Bob (see step 2), they would be able to decrypt any message that were sent between Alice and Bob in the future.

To solve this problem, we can use `asymmetric` key pairs. The process would look something like this:

1. Alice generates a `asymmetric` key pair (a `public` and `private` key).
2. Bob generates a `asymmetric` key pair (a `public` and `private` key).
3. Alice and Bob exchange their `public` keys with each other. It doesn't matter if anyone else captures the `public` keys because they are not used to encrypt/decrypt messages.
4. Alice writes a message and then encrypts it using Bob's `public` key.
5. Alice sends the encrypted message to Bob. It doesn't matter if anyone else captures the message because it is encrypted using Bob's `public` key.
6. Bob receives the message and decrypts it using his `private` key.

In this process, the `public` keys are used to encrypt the message and the `private` keys are used to decrypt the message. This means that if anyone were to capture the `public` keys while they were being sent to Bob (see step 3), they would not be able to decrypt any message that were sent between Alice and Bob in the future.

Some other things to note:

- `asymmetric` key pairs are computationally expensive which means that they are slower at encrypting/decrypting messages than `symmetric` keys. This difference is usually not noticeable unless you are encrypting/decrypting a large amount of data.
- `asymmetric` key pairs are usually binded to a specific 'actor' (e.g. Alice, Bob, etc.) which means that you can use the `public` key to prove that a message was sent by a specific 'actor' (e.g. Alice). On the other hand, `symmetric` keys are usually shared between two 'actors' (e.g. Alice and Bob) which means that you can use the `symmetric` key to prove that a message was sent between two specific 'actors' (e.g. Alice and Bob).

## Key types

| name         | algorithm | type         | description                                              |
| ------------ | --------- | ------------ | -------------------------------------------------------- |
| `SecretKey`  | `aes256`  | `symmetric`  | used to encrypt/decrypt messages                         |
| `PassKey`    | `pbkdf2`  | `symmetric`  | used to encrypt/decrypt messages with passphrase         |
| `SharedKey`  | `aes256`  | `symmetric`  | used to encrypt/decrypt messages between two `ecdh` keys |
| `PrivateKey` | `ecdh`    | `asymmetric` | used to derive `SharedKey`                               |
| `PublicKey`  | `ecdh`    | `asymmetric` | used to derive `SharedKey`                               |

### Secret Key

The `SecretKey` is a `symmetric` key that is used to encrypt/decrypt messages. The key uses the [AES-256-GCM algorithm](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#aes-gcm).

### Pass Key

The `PassKey` is a `symmetric` key that is used to encrypt/decrypt messages **with a passphrase**. The key uses the [PBKDF2 algorithm](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey#pbkdf2) which derives a `SecretKey` from a passphrase. In other words: passphrase -> `PassKey` -> `SecretKey`.

The `PassKey` is more user-friendly than the `SecretKey` because it allows the user to use a passphrase that is easier to remember than a 32-byte key.

### Private Key and Public Key

The `PrivateKey` and `PublicKey` are `asymmetric` keys that are used to derive a `SharedKey` (see below). The key pair uses the [ECDH algorithm](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey#ecdh) which is a key agreement protocol that allows two parties to derive a shared secret from their `PrivateKey` and `PublicKey` respectively. It is also worth noting that the ECDH algorithm uses the `P-256` curve.

The ECDH algorithm was chosen over [RSA](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#rsa-oaep) because it performs better in terms of speed and security [1](https://api.semanticscholar.org/CorpusID:203655425) [2](https://api.semanticscholar.org/CorpusID:975015).

Another reason for choosing the ECDH algorithm is that it is the preferred algorithm for 

### Shared Key

The `SharedKey` is a `symmetric` key that uses the [AES-256-GCM algorithm](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#aes-gcm) to encrypt/decrypt messages. More importantly, the `SharedKey` is derived from a `PrivateKey` and `PublicKey` pair however, the keys do not need to belong to the same key pair.
