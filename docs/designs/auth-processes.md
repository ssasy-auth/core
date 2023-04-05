# `ssasy` process view

The purpose of this project is to create a usable and secure self-soveriegn user authentication system. This is acheived using two logical modules:

1. `challenge-mod.ts` - contains the logic for generating and solving challenges
2. `crypto-mod.ts` - contains the logic for encrypting and decrypting messages and creating and verifying signatures

These logical modules allow users and services to perform the following user authentication processes:

1. User Registration - allows services to confirm that a user has control of a key pair and to associate a key pair with a unique identifier
2. User Login - allows services to confirm that a user has control of a key pair associated with a unique identifier

to register and login to a system without the need for a central authority. The processes also enable services to verify that a user is who they claim to be without the need for a central or federated authority.

## Logical Modules

The logical modules are responsible for creating and solving challenges, encrypting and decrypting messages and creating and verifying signatures.

### Challenge module

A challenge consists of the following properties:

- `nonce` - A cryptographically secure random number that is used to generate the challenge's solution. The nonce is only used once and is discarded after the challenge is solved to prevent replay attacks.
- `timestamp` - The time at which the challenge was created. Challenges are only valid for a short period of time (5 minutes) to prevent replay attacks.
- `verifier` - The public key of the user that created the challenge.
- `claimant` - The public key of the user that will solve the challenge.
- `solution` - The hash of the challenge's nonce. The solution is used to verify that the challenge was solved correctly.

It is worth noting that the challenge is not encrypted. It is just a protocol that is used during the user authentication process.

At a high-level, the challenge module exposes three functions that allow users to create, solve and verify challenges.

The `createChallenge` function is used to create a challenge. This includes generating a cryptographically secure random number as well as a timestamp. The function also takes the public keys of the user that created the challenge and the user that will solve the challenge. The function returns a challenge object.

The `solveChallenge` function takes a challenge and the public key of the claimant that will solve the challenge. Initially, the function performs a number of controls on the challenge and then generates the solution. Firstly, it checks that the challenge has not expired and that the public key of the claimant matches the claimant property of the challenge. If the challenge has expired or the public keys do not match, the function throws an error. If the challenge is valid, the function generates the solution and sets the solution property of the challenge. The function then returns the challenge object.

The `verifyChallenge` function takes a solved challenge and the public key of the verifier that will verify the challenge. Just like the `solveChallenge` function, the `verifyChallenge` function checks that the challenge has not expired and that the public key of the verifier matches the verifier property of the challenge. If the challenge has expired or the public keys do not match, the function throws an error. Aftwerwards, the function verifies that the solution is correct. A solution is correct if the hash of the challenge's nonce matches the solution property.

On it's own, a challenge is redundant as a means to verify ownership of a public key. This is because the ECDH algorithm used to generate a shared key between two parties can be used to verify that both parties have control of their respective public keys. That is to say, a user can can verify that the other user has control of their public key by generating a shared key, encrypting a simple message and then asking the other party to decrypt the message.

However, as part of a user authentication process, a challenge is used to verify that two parties have interacted with each other prior to the challenge being created which prevents the risk of phishing. This will be explained in more detail in the following sections.

### Crypto module

In the context of user authentication, a ciphertext consists of the following properties:

- `data` - the encrypted data as a base64 encoded string
- `iv` - the initialization vector used to encrypt the data
- `sender` - the public key of the user that encrypted the data
- `recipient` - the public key of the user that decrypted the data
- `signature` - a signature that the recipient can verify. This property is not always present.

The crypto module a number of function that support the user authentication processes.

The `generateNonce` function generates a cryptographically secure random number.

The `hash` function takes a text and returns a base64 encoded hash of the text using the SHA-512 algorithm.

The `encrypt` function takes a plaintext, shared key, the sender's public key and the recipient's public key. The function encrypts the data using the shared key and an initialization vector which consists of random set of numbers. The function then returns a ciphertext object as described above.

The `decrypt` function takes a ciphertext and a shared key and returns the plaintext. This operation uses the shared key and the initialization vector attached to the ciphertext to decrypt the data.

The `sign` function takes a plaintext and a private key and returns a ciphertext object instead of a digital signature. This is because this function implements a 'hackey' digital signature scheme to overcome the limitations of the ECDH algorithm. This is because the ECDH algorithm supports key derivations (shared keys) and the ECDSA algorithm supports digital signatures. This means that, if a user wants to encrypt/decrypt and sign/verify, they would have to manage two key pairs. This is not ideal, especially for users that are not familiar with cryptography. Therefore, the `sign` function derives the public key from the private key and then encrypts the plaintext using the shared key between the private and public key pair. The encryption becomes the 'digital signature'.

The `verify` function takes a ciphertext and a private key and returns the plaintext. This operation uses the shared key between the private and public key pair to decrypt the data.

## User authentication processes

The user authentication process ensures that a user is who they claim to be. In the context of this project, authentication is achieved by verifying that a claimant has control of a key pair that is associated with a unique identifier using a challenge-response protocol.

