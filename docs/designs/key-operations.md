# `ssasy` key operations

The goal of this project is to create a usable and secure user authentication system. In order to acheive this, basic cryptographic operations were implemented as building blocks and then used to implement user authentication.

## building blocks

Building blocks refers to the operations that are used within the user authentication process to acheive some goal. These operations are not intended to be used directly by the user, but are used by the user authentication system more than once.

### key derivation

### encryption and decryption

### friendship bracelets - a hackey way to sign messages

Digital signatures are a way for a user to verify that **they** sent a message. In an ideal world, you would use a private key to sign a message and then use the corresponding public key to verify the signature. More importantly, anyone can veryify the signature using the corresponding public key.

However, in this project, signatures are only used by the creator of the signature to verify that they did indeed create the signature.

Unforunately, the WebCrypto API does not support signing and verifying messages with ECDH keys, which are the keys that are used in this project.
Instead, you need generate another set of keys using the ECDSA (elliptic curve digital signature algorithm) algorithm. This means that you need to generate two sets of keys for each user (one for encryption and one for signing). This is not ideal because it means that you need to manage two keys for each user.

To overcome this, the project uses 'friendship bracelets' to sign messages. These are essentially meesages that are encrypted with the user's key pair. The content of the message is irrelevant, but it is important that the message is encrypted with the user's key pair. This means that the message can only be decrypted with the user's private key. This is a hackey way to sign messages, but it works.

### challenge-response

The challenge response ritual is a three-step process that is used to verify that a claimant is who they claim to be.

#### step 1: generating a challenge **as a verifier**

1. generate a random number
2. create a challenge with the random number, the claimant's public key, your (the verifier's) public key and a timestamp
3. encrypt the challenge with the claimant's public key

```json
{
  "nonce": "random number",
  "claimant": "claimant's public key",
  "verifier": "verifier's public key",
  "timestamp": "timestamp"
}
```

#### step 2: solving a challenge **as a claimant**

#### step 3: verifying a solution **as a verifier**

## user authentication

User authentication refers to the process of verifying that a user is who they claim to be. In traditional user authentication systems, this is acheived by registering a user with a unique identifier (e.g. email or username) and a password. Once the user is registered, a system can verify that the person claiming to be `alice@mail.com` is actually `alice@mail.com` by asking the claimant to provide the password that was used to register `alice@mail.com`.

However, in the context of public-key cryptography, this means that the user is in possession of the private key that corresponds to the public key that is provided by the user. The remainder of this section describes how this project implements user authentication.

For the rest of this section, I will user Alice as a `claimant` and example.com as a service that plays the `verifier` role.

### registration

1. Alice generates a key pair
2. On example.com, Alice initiates a registration request by providing her public key
3. The verifier generates a challenge

### login
