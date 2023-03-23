# encryption

Encryption is the process of scrambling a message so that it becomes unreadable. Decryption is the process of unscrambling a message so that it returns to it's original (and readable) form. In order to encrypt and decrypt a message, a passphrase is required. This passphrase is called a key.

## sending messages

Let's say Alice and Bob want to communicate using encryption, first they must decide on a key that they will use to encrypt and decrypt messages. Then, they must find a way to deliver the key to each other without revealing it to anyone else. This is called key exchange.

Once the two parties exchange keys, they can begin sending messages:

1. Alice comes up with a message and encrypts it using the key
2. Alice sends the encrypted message to Bob
3. Bob decrypts the encrypted message using the key and reads the original message
4. Bob comes up with a reply and encrypts it using the key
5. repeat...

This is the basis of a secure communication. However, the problem with this type of encryption is that if someone else were to capture the key during the key exchange, they could then decrypt all of the messages that are sent between the Alice and Bob. If they wanted to be extra mean, they could also send messages to Alice pretending to be Bob, or vice versa and the receiver would have no way of knowing.

## asymmetric encryption

In order to solve the key exchange problem, some mathematicians[^asymmetric-encryption] came up with a solution called asymmetric encryption which involves two mathematically related keys per person. The first key is used to encrypt messages and the second key is used to decrypt messages. This is called a public key and a private key, respectively.

The reason why asymmetric encryption solves the key exchange problem is because it no longer matters whether someone has the key that Alice exchanges with Bob. This is because as long as Bob encryptes his message using Alice's public key, only Alice's private key can decrypt it and vice versa.

Let's repeat the message exchange steps above but using asymmetric encryption:

1. Alice asks Bob for his public key
2. Alice writes a message and encrypts it using Bob's public key
3. Alice sends the encrypted message to Bob
4. Bob decrypts the encrypted message using his private key and reads the original message
5. Bob asks Alice for her public key
6. Bob writes a reply and encrypts it using Alice's public key
7. repeat...

Even if someone were to capture Bob's public key in step 1, they would not be able to decrypt the message encrypted in step 2 because they do not have Bob's private key. The same applies to Alice's public key in step 5.

## encryption and user authentication

So far, we have discussed encryption, decryption, and key exchange for sending messages. We have also discussed how asymmetric encryption solves the key exchange problem. One thing that we have not discussed yet is how asymmertic encryption can be used to authenticate users.

Let's say that Alice has a web shop and she wants to make sure that only registered users can view and purchase items. At a high level, this means implemening a registration process and a login process.

Using asymmetric encryption, Alice could **register** users through a challenge-response protocol:

1. Bob wants to register with Alice's web shop so he sends his public key to Alice
2. Alice wants to make sure that Bob is in control of the private key that corresponds to the public key that he sent her, so she generates a random number and encrypts it using Bob's public key and asks him to decrypt it
3. Bob uses his private key to decrypt the random number and sends it back to Alice
4. Alice compares the decrypted random number with the original random number
5. If they random numbers match, she registers Bob as a user and saves his public key

Alice can use a similar challenge-response protocol for the **login** process:

1. Bob wants to login to Alice's web shop so he sends his public key to Alice
2. Alice verifies that Bob is a registered user by comparing his public key with the list of registered users
3. If Bob is a registered user, Alice generates a random number and encrypts it using Bob's public key and asks him to decrypt it
4. Bob uses his private key to decrypt the random number and sends it back to Alice
5. Alice compares the decrypted random number with the original random number
6. If they random numbers match, she grants Bob access to the web shop

[^asymmetric-encryption]: [Diffie and Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) came up with the concept and [Rivest, Shamir and Adleman](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) came up with the first practical implementation.
