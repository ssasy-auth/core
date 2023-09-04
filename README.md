# SSASy

SSASy is a **self-sovereign authentication scheme** that enables users to authenticate themselves in usable, secure and decentralized manner without without relying on a third party (e.g. Google, Microsoft, Facebook, Twitter).

## Features

- [x] Generate crypto graphic keys
- [x] Export and Import keys
- [x] Encrypt and decrypt data
- [x] Prove ownership of private key

## Why use SSASy?

> To be sovereign is to have supreme power and to be free from external control or influence.

`Self-sovereign authentication schemes` reduce the number of security risks that are associated with user authentication for two stakeholders:

- `user` - the person that needs to register and login into one or more services
- `service` - (a.k.a the `verifier`) the website or platform that needs to verify the identity of the user before granting access to a resource

With the help of `cryptography`, services no longer need to store user credentials in a database. This also means less risk of data breaches and less risk of user credentials being stolen. On the other hand, users no longer need to remember complex and hard-to-guess passwords for each service they use. Instead, they can rely on public key cryptography to prove their identity which is much more secure and convenient.

To find out more about SSASy, navigate to the [docs](docs/introduction.md) for a more detailed explanation.

## Usage

The library exposes a number of modules that can be used to generate cryptographic keys, encrypt and decrypt data and prove ownership of private keys. The modules are described below.

### Wallet

The `Wallet` class provides an abstraction layer for performing cryptographic operations... most notably, engaging in a challenge-response protocol to prove ownership of a private key. The `Wallet` class is built ontop of the `CryptoModule` and `ChallengeModule` modules and requires a `PrivateKey` to be which can be generated using the `KeyModule` module (see [Generate keys](#generate-keys)).

```ts
import { Wallet } from '@ssasy-auth/core';

// Alice and Bob initiate their wallets
const aliceWallet: Wallet = new Wallet(alicePrivateKey);
const bobWallet: Wallet = new Wallet(bobPrivateKey);

// Alice creates a challenge that only Bob can solve
const challenge: string = await aliceWallet.generateChallenge(bobPublicKey);

console.log(challenge);
/* 
ssasy://ciphertext?data="1%2FbPcyk9VSH6pyHeIEZPvp4BTe%2B0jg50TNZ8yvDV%2B8ji7LI6aT8rd9W8aIZ9RgKXE%2FE4QQRPMuXhiDn9oa5iVnTT1H0%2FRbtmOyQNUpvmKJSnCT%2FTQ8fqtaJ0rsbjKvJq4LvLXcM%2BBW2XjSVUA9ZWcfTmcJIaZZmrY7HZBQlNJFjINmT%2FTSZLPNzYF1S8jch4JBCJYrhRvoO9kCWW284rnac391%2B9R3qNSCOJmybzsYB9GqTcnFsyDIqVwrvxkTA5d1JsjekjSMqFxW0AZyAeM6OpzD0jJNPdnJfedJseYrVSV5qb57PaqUSBCYRnSPxQDkf7m9hKrCJlFkY8CK5a1QE8Txj2ijghp%2FLhPzB9zLpasBv7kOzsUNCY1S2IP%2Fev2M%2FMh5TSZaGfwQgOozUus7q1C5eI7iln%2Bcf9qGX7qQ3XbmxND6v1CEmdE%2FPWfGicCJo6Y%2FbIDLTg654RjcD20kzFOorAgsWGBBFRfaiB30kwbLGVMc0WbwQQAc3PZo%2FC6SWiqWqjKkfm2VICYatkdJk8QJfjAzVCLMU0Zt8T4k7rspij3x5aB%2BdsQ3XQQuYrBrYox%2FPmhFp880TCpOeDtKObNcRh1AMorC3VGS5UQ8Z1LvWVygLfGAS%2FvV6OGYs9hwYbaGOmWpX7V8IbeONKOiipQKsQkHqukVFHF2jtjcY6qOf9TpsD9c5BuWPqIMp7nJRKtOWICE5rj2uhuF5IDcKAkMqAkIIVlfCBX7rJdodOUil25aPY4A%3D%3D"&iv="WCIZTcrXVHolhGEdg99dRA%3D%3D"&sender="ssasy%3A%2F%2Fkey%3Ftype%3D'public-key'%26c_key_ops%3D'%255B%255D'%26c_ext%3D'true'%26c_kty%3D'EC'%26c_x%3D'yAJUqP84ykekPkDehELdU119jkw87ivtEbuhNBlJ4CA'%26c_y%3D'zMShmX6guy77a3s7Vy23zrJ4iA1o7QjWANhP9fN6FGQ'%26c_crv%3D'P-256'"&recipient="ssasy%3A%2F%2Fkey%3Ftype%3D'public-key'%26c_key_ops%3D'%255B%255D'%26c_ext%3D'true'%26c_kty%3D'EC'%26c_x%3D'Zv7tbbihorNs06pBK7R52IxXALXAdGfA28iwwv4VM38'%26c_y%3D'S7J8tjbsMUhEYIMNVpkoMAdGay32G_90P4IRv_6JRk8'%26c_crv%3D'P-256'"
*/

// Bob solves the challenge
const challengeResponse: string = await bobWallet.generateChallengeResponse(challenge);

console.log(challengeResponse);
/*
ssasy://ciphertext?data="qQ8aTuXQ8nE92D4ifYVYQYmA8fDhRZWVPMz0qKky9Wn489wKLlmxyCcAEh9jlHhhsfHPjYRGrxh2e%2F3gSwloBMq0SZn1C7qkThjx4U3hWirpw6hpDxX9fYRt0QLNIiajt4xFJ0npUFHDs0fXP1kF1WsN3mZuzvTvmrCgAQe4o30KMZY3T%2FUKSR4EN6cX8h%2FJTM0wVLq9bLB4SDFiRC38KaBroHht6aBEwdOjAUnFmPzldOc9JpZVMA3Iq7lBoEn4i3H%2BbWXDxW20dJ4LboGKvKsH1TQW9SqZN0xEmWOAAaAw9zgZEnFBgdWNO91FowMAFsayTJ8KnWDfL6fm1YGxOvXhA1C7HwB6RG72wxZSQBSQsjrbnxbJOPtranlqoJOO%2BWtuXHpv4d5gSWBv3UDhbzNLfp8yLCKJljHqFQ6rxkpmBbEw%2BZEwtIua6ZcDqauw4h1mcQJmKk4Kh%2BLxLyIeqySoTAoR7bxl372Y1W%2Fwbp4GTLA0joMiz7Y3wsFRQAXFkGPCI%2FLDD72PD%2F4yhXrKSdQysCSCDzD6WzeRxQx%2BdFbQ3SpokJj7mqyC8rVLKSQcHiin6zRYd3zkhLTp7bs%2F8Ydc%2BCE%2B%2BNFD2G9VYpqKw%2FqUT9clGikw61aK1W6jdzyovGRThopEKGV%2BieunnOos4jx26xVB7hfazDv0%2BdWzFDDqcVNljS7FXw2F5OrmPnD6tS%2FlVBPh0V0C9782t3J2zFKHLWllGaofk6Zo1761XX%2F0tFiLaICh%2FGYXYPWE8IXEt3efknW0pcVP8ov2SyiHdl%2BpN%2F8a6WjbNvfFMhWGUhqLoMYHDhUh7u5grqKxN0Kp%2BAfcnJ8Prbfo3nX4%2FKY%2BstXjGi45AMXCoIseEK2cJnGtQP706bMmSo0lpPgUZ6IuOpCVQBgcqAk%3D"&iv="pRWaWlgRKSnclyN7xtta6w%3D%3D"&sender="ssasy%3A%2F%2Fkey%3Ftype%3D'public-key'%26c_key_ops%3D'%255B%255D'%26c_ext%3D'true'%26c_kty%3D'EC'%26c_x%3D'k5w7_TkyhQ7-fE_N2xlpg_8-IbBLPIA9-a4OqG4l7uo'%26c_y%3D'mup5E6qyLHs4jaXW8Yu-hXnMqX4WWaRjcUOLNtVYFhk'%26c_crv%3D'P-256'"&recipient="ssasy%3A%2F%2Fkey%3Ftype%3D'public-key'%26c_key_ops%3D'%255B%255D'%26c_ext%3D'true'%26c_kty%3D'EC'%26c_x%3D'eVQSpOQyC8hhM85bJdLvby0tVHpPq-u8NU9GmMbHqXE'%26c_y%3D'z22bRdKW47OY1sOakshhPKcMSwAOnnYfPh1DevGwzGQ'%26c_crv%3D'P-256'"&signature="ssasy%3A%2F%2Fsignature%3Fdata%3D'VKxgHA5SNZO4s2%252Fmi0eneeud%252FaEOIGq815l%252BZ3zIQSov6yNS4virKImffovg3IUiPSt8exWpCJ2kI20G%252BJRRNxtgaMU%252FS91J95g1vOjJSsVJ39GdUuvytLSOCw3%252FRtc3wfNROrw9kHaqBIGdfvqdzPb6r%252Fgnigso67Bp5b8%252FQ%252FUUKv%252FHFpAjpbyJux5nw99u6afyuOvOw5vHghhNTLZBtddTF95wssAWJZF4HuCo5ylHPx%252B6dBdTsum0GNs6hI6zP%252FcU9cW2wrTGNlPB%252FEIBoHGOvwmZklN40dtkdLcGWYVWf5fA5fUf9njp%252FKog9RSIS53UorvGvWlmkC%252BPe9kCSZJOst5MTOOmuDnQuQDXeOFy%252Fmg0tRjhFTlmtMs6ABy%252FARePHlWdq4rSV19XSVDwti5d1vikiolcJG7Pk5N3fd%252FBbfd9PfPp3oiBJkAAlV8HjGVCi7rtv2h6b81DJRym2p4DFPGjAkX6VaSZPbK8ex8hwCcyyU7MlyxTF79hZ%252FLUbDbH34Izy13vjBrLjHbInSAlXAYaKYz%252BWYoDtWGTh7cc3WjsNK%252B5gkybPjPaqr%252FkNzWZCo9Ew60kcKkatNpv1hiC6o4qGWHaFaEYe%252B6Oa2TuCRKOx4HQFVKeQYzsf%252FK4Yrfg8VGlfxJ60ruyE3Skv%252FApRDxq6AxyVo%252BcDz8IdkuwUlgjFV5%252B55oZ5N5YtHULVbEam9K%252BJVr3UTfQMXF7i6pVa5P%252FS2jbzn9QAKQygydCwDuTJV9FT3FE3wiWXkF7Fe3OHQUOkPtEPUFgk5SVEhJQuC6dtu%252FaXoHTHermYOv6nRxn8ZDrhBViFo2eF0sy7fos2Yz5Au5frtrqBfbAYQTAS5YshE5oUyO4mR6p5%252FAWOTxIQHRFNNxg9b2O2c61j2agXGKL9yQ%253D'%26iv%3D'tYEG4YhxsUhnltIY2yRDCA%253D%253D'"
*/

// Alice verifies the solution (null if invalid)
type Result = { publicKey: string, signature?: string } | null;
const result: Result = await aliceWallet.verifyChallenge(solution);

console.log(result);
/*
{
  publicKey: "ssasy://key?type=\"public-key\"&c_key_ops=\"%5B%5D\"&c_ext=\"true\"&c_kty=\"EC\"&c_x=\"rrZtymmL2KUO3eoBKiKCwVJDlhT0DN1M2ECqtOM_Hmc\"&c_y=\"eatDscvvITpsRo9eYM_dpVuJZyc-3uz1e4yIogLcBQg\"&c_crv=\"P-256\"",
  signature: "ssasy://signature?data=\"294073dtNBXnpr9pzmLKkSVlD6JLeeUX1tGfZU94x7XAmBWqLHrqEI88ll4xOT99NM1ySg1eoxXtgTpZjAl1PHkIOH%2Fq%2BqgnxqK%2BU8LdvDBJ%2FvEapGEvFGPS8ymSBFZoePM776kL71tTFlkBGzRzPm%2B9vzW1fEsZeFkerskHJ4BNYh5yvnwMqqh8Az9duABHFRR%2FSYqb%2Fnr7NSsavOXdu%2FqJxGdeRKYDhNTQzzuKp3d3tZnGyWgir2%2BoEW0rLy5bLBEXY3Ycjw%2FDnDAxa5IFn75ERaYAjYZkIf5skk7gfKIcnPbqX8RdFVAWEplI7U2q%2BPGeHJsk6lCgzEAs7uwkXIgt9e%2Fe6oEKjEIs38P3Az4VLds2rezg8Pgnff2G2%2Bp2nUW4RdGIP7RXTYXBD3ljfMBYlWrYQXwx7u%2Fj6B5SvAFG%2BQs0PdaF4uZYrVX5JAPIJ2KH5zRRj2A1jM%2FOd6w%2F2skmdVh7S1SxtrNbo1uAHmxHCu6HnXt%2FBBkzBhjtWEp%2BRtyL3%2F3Xs7P8pvZjGWkjfdXRL2ADZ%2FR0JwYYt7bLKeH7fmeRpjNQe9Vkj7cpw82zT%2Bx4Nq%2FCbeX8p30C1d%2F%2BZ9PHn%2B25tJbTnjCb%2BN%2FP3Y4EbvS8d8maw9nA1OI2F1Ga6Gxm78ZKin5cFmp0DWXnI27sXEcl8gGX1NCmZmozKU8KXF5Sq7XcExcPHAo4bCEXMq%2FH5Wxg1kkEVmWy3ShCQDfht7xxwLSf6KZ2ROcnek5UR201jh5TklK3ZLHBEfynh7y16GplNXgT5Y29NDHiyOOirtc1MSCZlJYa9xIHCUWLmhOlObD15gTKr584QWv%2FdTTb%2FOfRVyzIvyL1mE%2BJuLoDSxjvSmPgoxxaud7LIK2qL5r%2Fc%2B1rW%2BP3G2uBENU4CgD1dMN8BbU%3D\"&iv=\"tVMN%2FPoA375mfj0nZRwHxQ%3D%3D\"",
}
*/
```

### Generate keys

Generate symmetric, asymmetric and password-based keys (see [`key-interfaces.ts`](./../src/interfaces/key-interface.ts)) using the `KeyModule`. Each key has a `type`, `domain` (optional) and a `crypto` object that contains the cryptographic key. To find out more about the algorithms used to generate the keys, check out the [`algorithm.ts`](./src/config/algorithm.ts).

```ts
import { KeyModule } from '@ssasy-auth/core';
import type { SecretKey, PrivateKey, PublicKey, PassKey, SharedKey } from '@ssasy-auth/core';

// create symmetric key
const key: SecretKey = KeyModule.generateKey();

// create private key
const privateKey: PrivateKey = KeyModule.generatePrivateKey();

// create public key
const publicKey: PublicKey = KeyModule.generatePublicKey({ privateKey: privateKey });

// create shared key
const otherPrivateKey: PrivateKey = KeyModule.generatePrivateKey();
const otherPublicKey: PublicKey = KeyModule.generatePublicKey({ privateKey: otherPrivateKey });
const sharedKey: SharedKey = KeyModule.generateSharedKey({ privateKey: privateKey, publicKey: otherPublicKey });

// create pass key
const passphrase: string = "i like frozen pizza";
const passKey: PassKey = KeyModule.generatePassKey({ passphrase: passphrase });
```

### Export and import cryptographic keys

This library uses cryptographic keys within a Secure Context (see [Secure Context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts)) however, it is sometimes necessary to export keys outside of the Secure Context for storage on a database or server, for example. Keys can be exported as a `RawKey` JSON object (see [`key-interfaces.ts`](./../src/interfaces/key-interface.ts) for more information). Naturally, keys can also be imported from a `RawKey` object back into the Secure Context.

```ts
import { KeyModule } from '@ssasy-auth/core';
import type { PrivateKey, RawKey } from '@ssasy-auth/core';

// generate key
const privateKey: PrivateKey = KeyModule.generatePrivateKey();

// export private key
const rawKey: RawKey = KeyModule.exportKey(privateKey);

console.log(rawKey)
/* 
{
  type: 'private-key',
  domain: undefined,
  crypto: {
    key_ops: [ 'deriveKey' ],
    ext: true,
    kty: 'EC',
    x: 'wfU6gcQj3KKfZTMfNKLi_v93-SJgwdQ3ZQ6pO__MLnM',
    y: 'FVrQkqWZ02Mo_iiSA3UeMIMBQNS0gwtjfjBkT4Z7F7k',
    crv: 'P-256',
    d: 'y7EHPmHnI4KSA-ocCHXnIGb7ZzxdpmAmgAMezNPvr9I'
  }
}
*/

// import private key
const importedPrivateKey: PrivateKey = KeyModule.importKey(rawKey);

console.log(importedPrivateKey)
/*
{
  type: 'private-key',
  domain: undefined,
  crypto: {
    type: 'private',
    extractable: true,
    algorithm: { name: 'ECDH', namedCurve: 'P-256' },
    usages: [ 'deriveKey' ]
  }
}
*/
```

#### Encrypting and decrypting data

Encryption enables users to exchange information in a public space (i.e. the internet) without revealing the contents of the message to third parties. The `CryptoModule` can be used to encrypt and decrypt data using a symmetric key (i.e. `SecretKey`, `PassKey` or `SharedKey`).

```ts
import { KeyModule, CryptoModule } from '@ssasy-auth/core';

// create PassKey (password-based) cryptographic key
const passphrase = "n0b0dy_kn0ws-that_I_like-t0_heat_my-pizza_in_the-micr0wave";
const passKey = await KeyModule.generatePassKey({ passphrase: passphrase });

// encrypt payload
const payload = "I like pizza";
const ciphertext = await CryptoModule.encrypt(passKey, payload);

console.log(ciphertext);
/*
{
  data: 'o9S8FnA6qYzEiAnM+ZMprLrz5tzmcSs9mt4RdA==', <-- encrypted data
  iv: Uint8Array(12) [ <-- initialization vector
     84, 126,  5, 235,  37,
    108, 227, 90,  64, 239,
    200, 116
  ],
  salt: Uint8Array(16) [ <-- salt for the key derivation function
     77,  86, 112, 149,  33,
    143,  66, 165, 121,  63,
    130, 217, 175,  60, 221,
    133
  ],
  sender: undefined, <-- sender of the message (optional)
  recipient: undefined <-- recipient of the message (optional)
}
*/

// decrypt ciphertext
const decryptedMessage = await CryptoModule.decrypt(passKey, ciphertext);

console.log(decryptedMessage);
/* 
'I like pizza'
 */
```

### Signing and verifying data

Sometimes, it is necessary to prove that a message was sent by a particular sender. The `CryptoModule` can be used to sign and verify data using a private key (i.e. `PrivateKey`).

```ts
import { KeyModule, CryptoModule } from '@ssasy-auth/core';
import type { PrivateKey, StandardCiphertext } from '@ssasy-auth/core';

const privateKey: PrivateKey = await KeyModule.generatePrivateKey();

const payload = "I like pizza";

// sign payload
const signature: StandardCiphertext = await CryptoModule.sign(privateKey, payload);

console.log(signature);
/*
{
  data: "dfnWJK9IyT6cu+EgfWGWkA/VgwA3RZm/MO9E",
  iv: "6BG4AEJIBgAR1WdNKNzWEw==",
  salt: undefined,
}
*/

// verify signature (null if invalid)
const verifiedSignature: string | null = await CryptoModule.verify(privateKey, signature);

console.log(verifiedSignature);
/*
'I like pizza' 
*/
```

### Hashing data

Hashing is a one-way (output cannot be reverse engineered) function that transforms data into a fixed-length string. It is often used to quickly compare data without revealing the contents of the data. You can hash data using the `CryptoModule`.

```ts
import { CryptoModule } from '@ssasy-auth/core';

const payload = "I like pizza";

// hash payload
const hash: string = await CryptoModule.hash(payload);

console.log(hash);
/* 
"MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw=="
*/
```

The `CryptoModule` can be used to sign and verify data using an asymmetric key (i.e. `PrivateKey` or `PublicKey`).

### Serialize and deserialize resources

SSASy resources (i.e. keys, challenges, ciphertexts) can be serialized and deserialized using the `SerializerModule` module. This transforms a resource object into a Uniform Resource Identifier (URI) string that can be used to transfer and store resources. It is worth noting that the params in the URI string are encoded using the `base64url` encoding scheme to ensure that the URI string is URL safe.

```ts
import { KeyModule, SerializerModule } from '@ssasy-auth/core';
import type { SecretKey, RawKey, StandardCiphertext } from '@ssasy-auth/core';

const key: SecretKey = await KeyModule.generateKey();

const serializedKey: string = SerializerModule.serialize(key);

console.log(serializedKey);
/* 
ssasy://key?type="secret-key"&c_key_ops="%5Bencrypt%2Cdecrypt%5D"&c_ext="true"&c_kty="oct"&c_k="caKNtCfken0XOycfTGUgdIpu3jUaYZ8tqHbho7-e_1Q"&c_alg="A256GCM"
*/

const payload = "I like pizza";
const encryptedData: StandardCiphertext = await CryptoModule.encrypt(key, payload);

const serializedCiphertext: string = SerializerModule.serialize(encryptedData);

console.log(serializedCiphertext);
/* 
ssasy://ciphertext?data="hWbP06ueJRokk3byMi2AIxCfUXrjhc6oG3Q%2FMzi1"&iv="3b7Ykn9abiYBKl7B3NTAmg%3D%3D"
*/
```

## Change log

See the [changelog](docs/changelog.md) for more information.

## Contributing

Feel like contributing? Great! Please read the [contribution doc](/docs/contributing.md) for more information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file, in the root of the project, for details.
