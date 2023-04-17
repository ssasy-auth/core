# `ssasy` process view

The purpose of this project is to create a usable and secure self-soveriegn user authentication process that enables a verifier to verify that a user is who they claim to be. There are two main ingredients to this process:

- `claimant` - the user that is claiming to have control of a public key
- `verifier` - the user or service that is verifying that the claimant has control of a public key

That being said, the process is acheived using three logical components:

1. `challenge-mod.ts` - contains the logic for generating and solving challenges
2. `crypto-mod.ts` - contains the logic for encrypting and decrypting messages and creating and verifying signatures
3. `wallet.ts` - performs the user authentication process by abstracting the challenge and crypto modules

## Logical components

### Challenge module

The challenge module is responsible for generating and solving challenges as part of a challenge-response protocol. In this project, a challenge consists of the following properties:

- `nonce` - A cryptographically secure random number that is used to generate the challenge's solution. The nonce is only used once and is discarded after the challenge is solved to prevent replay attacks.
- `timestamp` - The time at which the challenge was created. Challenges are only valid for a short period of time (5 minutes) to prevent replay attacks.
- `verifier` - The public key of the user that created the challenge.
- `claimant` - The public key of the user that will solve the challenge.
- `solution` - The hash of the challenge's nonce. The solution is used to verify that the challenge was solved correctly.

It is worth noting that the challenge is not encrypted. It is just a protocol that is used during the user authentication process. At a high-level, the challenge module exposes three functions that allow users to create, solve and verify challenges.

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

### Wallet class

The wallet class is responsible for exposing functions that allow users to engage in a challenge-response protocol. The wallet achieves this by combinging the challenge and crypto modules into an abstracted set of functions: `createChallenge`, `solveChallenge` and `verifyChallenge`.

In order to follow along with the following paragraphs, it is best to apply the functions to an examples. That being said, let's assume that Alice, a claimant, wants to authenticate to a social media platform called Thoughts (verifier).

#### Creating a challenge with `createChallenge` as the verifier

The `createChallenge` function is used by the verifier to create an encrypted challenge for the claimant. The function takes the verifier's private key and the claimant's public key as arguments and then performs the following steps:

1. derives the verifier's public key from the private key
2. creates a challenge object using the verifier's public key, the claimant's public key and a nonce (cryptographically secure random number)
3. derives a shared key from the verifier's private key and the claimant's public key
4. encrypts the challenge object using the shared key to produce a ciphertext
5. sets the sender property to the verifier's public key and the recipient property to the claimant's public key

#### Solving a challenge with `solveChallenge` as the claimant

The `solveChallenge` function is used by the claimant to decrypt the ciphertext produced in the `createChallenge` function and to solve a challenge. The function takes the claimant's private key and the challenge object as arguments and then performs the following steps:

1. derives the claimant's public key from their private key
2. checks that the ciphertext's recipient property matches the claimant's public key
3. derives a shared key from the claimant's private key and the verifier's public key which is defined in the ciphertext's sender property
4. decrypts the ciphertext using the shared key to produce a challenge object
5. checks that the challenge object's claimant property matches the claimant's public key and that the challenge object's verifier property matches the ciphertext's sender property. This is to ensure the integrity of the challenge object and that the challenge object and the ciphertext are associated with the same parties
6. checks that the challenge object has not expired
7. solves the challenge by hashing the challenge object's nonce property and setting the solution property of the challenge object to the hash
8. encrypts the challenge object using the shared key to produce a ciphertext
9. sets the sender property to the claimant's public key and the recipient property to the verifier's public key
10. produces a digital signature of the solved challenge object using the claimant's private key and sets the ciphertext's signature property

#### Verifying a challenge with `verifyChallenge` as the verifier

The `verifyChallenge` function is used by the verifier to verify that the claimant has solved the challenge. The function takes the verifier's private key and the ciphertext produced in the `solveChallenge` function as arguments and then performs the following steps:

1. derives the verifier's public key from their private key
2. checks that the ciphertext's recipient property matches the verifier's public key
3. derives the shared key from the verifier's private key and the claimant's public key which is defined in the ciphertext's sender property
4. checks that the solution's verifier property matches the verifier's public key and that the solution's claimant property matches the ciphertext's sender property. This is to ensure the integrity of the challenge object and that the challenge object and the ciphertext are associated with the same parties
5. checks that the solution has not expired
6. checks that the solution's solution property matches the hash of the challenge's nonce property

## User authentication process

There are two possible scenarios that trigger a user authentication process:

1. Regsitration - The user (claimant) is registering for the first time to a service (verifier). This is important for a number of reasons, such as rationing resources, preventing fraud and other things.
2. Login - The user (claimant) is logging in to a service (verifier) that they have already registered.

### Constraints

The wallet handles both scenarios, registration and login, with a challenge response protocol mentioned in the previous section however there are some slight differences. In order to understand the differences, it is worth mentioning some constraints that this project must adhere to.

#### Claimants cannot store data

First of all, claimants have no means of storing data apart from their private key. This means that, unlike decentralized ledger applications, claimants cannot store data on the blockchain. Similarily, claimants cannot store data on a server or cloud storage since such methodologies include additional trust assumptions and security risks.

Another reason why claimants cannot store data is because this project is designed to be usable by people who may not have a lot of knowledge, experience or interest in authentication. This means that the user authentication, including key management, must be as simple as possible which would not be the case if claimants had additional responsibilities such as storing, remembering and managing data. Verifiers, on the other hand, have the means to store data which means that they can store their private key and the public keys of their users, among other things.

#### Claimants are vulnerable to a new type of 'phishing attack'

Not being able to store data, as a claimant, is a security vulnerability because it means that the claimant cannot keep track of all the services that they have registered with. As a consequence, this means that users can be tricked into logging in to a service that they have not registered with.

Although this does not seem harmless, at first, it means that a malicious service can impersonate a legitimate service and the user would never know. This also means that users may interact with a service that they have not registered with and, as a result, they may be charged for a service that they will not receive which is a form of fraud.

### Regsitration vs Login

As mentioned earlier, the regsitration and login processes are similar because they both use the challenge response protocol. However, there are some differences between the two processes.

A signature is just a solved challenge that is encrypted with the claimant's private key. Also, the claimant always signs the challenge object after they have solved it.

Consequently, the claimant's signature allows the verifier to prove that they have registered with a claimant which is important because it means that the claimant wallet can verify that the claimant has registered with the verifier which means that they are not being 'phished' by a malicious service as described in the [previous section](#claimants-are-vulnerable-to-a-new-type-of-phishing-attack).

What does this mean for the registration and login process?

From a regsitration point of view, it means that the verifier should store the claimant's public key AND the claimant's signature. This is because the claimant's public key is used for authentication and the claimant's signature is used to prove to the claimant that they have registered with the verifier.

From a login point of view, it means that the verifier must provide the claimant's signature along with the challenge object during the `createChallenge` function. This is because the `solveChallenge` function also accepts a `requireSignature` argument which controls three things:

1. the ciphertext's signature property must be set
2. the signature was produced by the claimant's private key
3. the signature, which is a solved challenge, should have a verifier property that matches the verifier's public key
