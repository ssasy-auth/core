# **_SSASy_**

> To be sovereign is to have supreme power and to be free from external control or influence ([Merriam-Webster](https://www.merriam-webster.com/dictionary/sovereign)).

SSASy is a **self-sovereign authentication scheme** that enables users to authenticate themselves in usable, secure and decentralized manner without without relying on a third party (e.g. Google, Microsoft, Facebook, Twitter). The scheme is based on two main concepts: (1) [Public Key Encryption](https://people.csail.mit.edu/alinush/6.857-spring-2015/papers/diffie-hellman.pdf) by Diffie and Hellman and (2) the [Self-Sovereign Identity](http://www.lifewithalacrity.com/2016/04/the-path-to-self-soverereign-identity.html) by Chirstopher Allen.

---

## Features

- [x] Generate crypto graphic keys
- [x] Export and Import keys
- [x] Encrypt and decrypt data
- [x] Prove ownership of private key

### Generate cryptographic keys

Generate symmetric, asymmetric and password-based keys that follow the structres defined in the [`key-interfaces.ts`](./../src/interfaces/key-interface.ts). The keys can be used for encryption and decryption based on the type of the key. To find out more about the algorithms used to generate the keys, check out the [`algorithm.ts`](./src/config/algorithm.ts).

```js
import { KeyModule } from 'ssasy';

/* create symmetric key */
const key = KeyModule.generateKey();

/* create private key */
const privateKey = KeyModule.generatePrivateKey();

/* create public key */
const publicKey = KeyModule.generatePublicKey({ privateKey: privateKey });

/* create pass key */
const passKey = KeyModule.generatePassKey({ passphrase: "i-like-to-heat-up-my-pizza-in-the-microwave" });
```

### Export and import keys

Key can be exporteded as a RawKey JSON object for flexible use (see [`key-interfaces.ts`](./../src/interfaces/key-interface.ts) for more information). To import keys, pass the RawKey object to the corresponding function.

```js
import { KeyModule } from 'ssasy';

const privateKey = KeyModule.generatePrivateKey();

/* export private key */
const rawKey = KeyModule.exportKey(privateKey); // function can export all types of keys (symmetric, asymmetric, password-based)

console.log(rawKey)
  //{
  //  type: 'private-key',
  //  domain: undefined,
  //  crypto: {
  //    key_ops: [ 'deriveKey' ],
  //    ext: true,
  //    kty: 'EC',
  //    x: 'wfU6gcQj3KKfZTMfNKLi_v93-SJgwdQ3ZQ6pO__MLnM',
  //    y: 'FVrQkqWZ02Mo_iiSA3UeMIMBQNS0gwtjfjBkT4Z7F7k',
  //    crv: 'P-256',
  //    d: 'y7EHPmHnI4KSA-ocCHXnIGb7ZzxdpmAmgAMezNPvr9I'
  //  }
  //}

/* import private key */
const importedPrivateKey = KeyModule.importKey(rawKey);
console.log(importedPrivateKey)
  //{
  //  type: 'private-key',
  //  domain: undefined,
  //  crypto: CryptoKey
  //    type: 'private',
  //    extractable: true,
  //    algorithm: { name: 'ECDH', namedCurve: 'P-256' },
  //    usages: [ 'deriveKey' ]
  //  }
  //}
```

### Encrypt and decrypt data

To encrypt data, you need a symmetric key and a payload as a `string`.

```js
import { KeyModule } from 'ssasy';
import { CryptoModule } from 'ssasy';

/* create password-based cryptographic key  */
const passphrase = "n0b0dy_kn0ws-that_I_like-t0_heat_my-pizza_in_the-micr0wave";
const passKey = await KeyModule.generatePassKey({ passphrase: passphrase });

/* encrypt payload */
const payload = "I like pizza";
const ciphertext = await CryptoModule.encrypt(passKey, payload);

console.log(ciphertext);
//{
//  data: 'o9S8FnA6qYzEiAnM+ZMprLrz5tzmcSs9mt4RdA==', <-- encrypted data
//  iv: Uint8Array(12) [ <-- initialization vector
//     84, 126,  5, 235,  37,
//    108, 227, 90,  64, 239,
//    200, 116
//  ],
//  salt: Uint8Array(16) [ <-- salt for the key derivation function
//     77,  86, 112, 149,  33,
//    143,  66, 165, 121,  63,
//    130, 217, 175,  60, 221,
//    133
//  ],
//  sender: undefined, <-- sender of the message (optional)
//  recipient: undefined <-- recipient of the message (optional)
//}

/* decrypt ciphertext */
const decryptedMessage = await CryptoModule.decrypt(passKey, ciphertext);

console.log(decryptedMessage);
// 'I like pizza'
```

### Challenge and response

To prove ownership, the `Wallet` class can be used to generate challenges and responses. The challenge is a string that can be sent to the recipient. The recipient can then use the `Wallet` class to generate a response that can be sent back to the sender. The sender can then verify the response to prove ownership of the private key. This can also be acomplished using the `CryptoModule` along with the `ChallengeModule` but the `Wallet` class is more convenient.

```js
import { Wallet } from 'ssasy';

/* Alice and Bob initiate their wallets */
const aliceWallet = new Wallet(alicePrivateKey);
const bobWallet = new Wallet(bobPrivateKey);

/* Alice creates a challenge that only Bob can solve */
const challenge = await aliceWallet.generateChallenge(bobPublicKey);

console.log(challenge);
//{
//  data: 'FVcXWRUto8gyMZpsm5VHKh9l5ZG5foQSCPOnpvky53d5ZboQI2/5jvY6bwA0QDEavkxX9MpjawfmKA+egV8c77hgtK0aJH4DW7AyCcPDywP8NUgyyXVDcJmyoa4eLEpdKSpDaMw3kZbk061WTnOdx8xk2idYSqDSN7MD0xByv9ryVBdJboqt11BqljVvsv0fpafsetKZpMDvsG9sEqt/CObvhpcy9/fctfnaUjENkpTX0/wtY8IvFIrz2WQmp091hnyG0l2ZgJlh7nG+l7NDWAT2zsOaIJaaDPW+ithLoHiutCDD8+3eaExRXCdp/zKRP1rUNTyvbY5XsGD6zf1MuZH7cwXedc96I36yHGyFDeRW9Ch45zHZA0ZZY3WBA+GKIuoTT0Xq+RBfxMq4Pt16AP95dne/rxUikGo91UgYF9Ddsb0Ecpl6OzDiQ/1TxYLanFXgnoaQ5+/23HHSBCdUAvtTLjbeS8S9hbIwtP0Y/bOOSY9HRYHj8gniFB6NXjmA3Quxd5L+5hmcm0Uc1jNNxk+pAdSoIfeDzRzvzdiK75c64Hzo8+H6gCmRsdFBOKTKGTH/fO/dnHJRX806Mz7yoNWqyBkk0mTeZtoFA1Bmwmk72DdCWffOxwXUpK4=',
//  iv: Uint8Array(12) [
//    143, 144,   6, 250,  87,
//    207, 109, 205, 187, 174,
//     15, 229
//  ],
//  ...,
//}

/* Bob solves the challenge */
const solution = await bobWallet.solveChallenge(challenge);

console.log(challenge);
//{
//  data: 'FVcXWRUto8gyMZpsm5VHKh9l5ZG5foQSCPOnpvky53d5ZboQI2/5jvY6bwA0QDEavkxX9MpjawfmKA+egV8c77hgtK0aJH4DW7AyCcPDywP8NUgyyXVDcJmyoa4eLEpdKSpDaMw3kZbk061WTnOdx8xk2idYSqDSN7MD0xByv9ryVBdJboqt11BqljVvsv0fpafsetKZpMDvsG9sEqt/CObvhpcy9/fctfnaUjENkpTX0/wtY8IvFIrz2WQmp091hnyG0l2ZgJlh7nG+l7NDWAT2zsOaIJaaDPW+ithLoHiutCDD8+3eaExRXCdp/zKRP1rUNTyvbY5XsGD6zf1MuZH7cwXedc96I36yHGyFDeRW9Ch45zHZA0ZZY3WBA+GKIuoTT0Xq+RBfxMq4Pt16AP95dne/rxUikGo91UgYF9Ddsb0Ecpl6OzDiQ/1TxYLanFXgnoaQ5+/23HHSBCdUAvtTLjbeS8S9hbIwtP0Y/bOOSY9HRYHj8gniFB6NXjmA3Quxd5L+5hmcm0Uc1jNNxk+pAdSoIfeDzRzvzdiK75c64Hzo8+H6gCmRsdFBOKTKGTH/fO/dnHJRX806Mz7yoNWqyBkk0mTeZtoFA1Bmwmk72DdCWffOxwXUpK4=',
//  iv: Uint8Array(12) [
//    143, 144,   6, 250,  87,
//    207, 109, 205, 187, 174,
//     15, 229
//  ],
//  ...,
//}

/* Alice verifies the solution */
const isValid = await aliceWallet.verifyChallenge(solution); // returns Bob's public key if valid, null otherwise

console.log(isValid);
//{
//  type: 'public-key',
//  domain: undefined,
//  crypto: CryptoKey {
//    type: 'public',
//    extractable: true,
//    algorithm: { name: 'ECDH', namedCurve: 'P-256' },
//    usages: [ 'deriveKey' ]
//  }
//}
```

## Documentation

To find out more about SSASy, start by checking out the [docs](./docs/introduction.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file, in the root of the project, for details.
