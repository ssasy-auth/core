# `ssasy` key generation

| name         | algorithm | type         | description                                              |
| ------------ | --------- | ------------ | -------------------------------------------------------- |
| `SecretKey`  | `aes256`  | `symmetric`  | used to encrypt/decrypt messages                         |
| `PassKey`    | `pbkdf2`  | `symmetric`  | used to encrypt/decrypt messages with passphrase         |
| `SharedKey`  | `aes256`  | `symmetric`  | used to encrypt/decrypt messages between two `ecdh` keys |
| `PrivateKey` | `ecdh`    | `asymmetric` | used to derive `SharedKey`                               |
| `PublicKey`  | `ecdh`    | `asymmetric` | used to derive `SharedKey`                               |
