# Managing buffers

Buffers are a way to store data in memory as it is being processed or transported. In the context of this project, there are two main types of buffers that are handled:

- `ArrayBuffer` - A raw buffer of bytes that can be used to store data within a fixed size. On its own, it is not very useful, but using a `ArrayBufferView` allows for easy access to the data in the buffer.
- `Uint8Array` - A `ArrayBufferView` with a fixed size of 8 bits per element. This is the most common type of buffer view used in this project.

Buffer are important in `SSASy` because they are used to process `initializations vectors`, `salts` and `hashes` which are fundamental to many cryptographic operations. However, the problem with buffers is that they cannot be stored as is. They must be converted to a string representation before they can be stored in a database or sent over the network.

According to this [stackoverflow thread](https://stackoverflow.com/questions/27014578/should-i-use-base64-or-unicode-for-storing-hashes-salts), the _'best'_ way to store a buffer is to convert it to a `base64` string. This is because `base64` strings are more compact than `hex` strings and are more efficient than `utf-8` strings. This is also supported by [chatgpt](https://chat.openai.com/chat/3949da35-efcd-4481-b719-4bb49af6b400) who adds that `utf-8` strings are not optimized for storing binary data which can cause data corruption/loss.

However, there are trade-offs in everything. In the case of `base64` encoding, a limited set of characters are supported (A-Z, a-z, 0-9, +, /) and the `=` character is used as padding whenever the length of the string is not a multiple of 4. On the other hand, `utf-8` encoding supports a much larger set of characters (e.g. `{` and `}`) and does not require padding.

## Buffers in SSASy and how they are managed

I list the buffers that are used in `SSASy` and how they are managed in the table below.

| #   | Component                                         | Property                       | In-Use       | At-Rest           |
| --- | ------------------------------------------------- | ------------------------------ | ------------ | ----------------- |
| 1   | [`CryptoMod`](../src/modules/crypto-mod.ts)       | `ciphertext.data` *              | `Uint8Array` | `string` (base64) |
| 2   | [`CryptoMod`](../src/modules/crypto-mod.ts)       | `ciphertext.iv`                | `Uint8Array` | `string` (base64) |
| 3   | [`CryptoMod`](../src/modules/crypto-mod.ts)       | `ciphertext.salt?`             | `Uint8Array` | `string` (base64) |
| 4   | [`KeyMod`](../src/modules/key-mod.ts)             | `key.salt` (as PassKey)        | `Uint8Array` | `string` (base64) |
| 5   | [`ChallengeMod`](../src/modules/challenge-mod.ts) | `challenge.nonce` (as PassKey) | `Uint8Array` | `string` (base64) |

### Special notice - Ciphertext Data

Special notice is given to the `ciphertext.data` property in `CryptoMod` which stores the encrypted data. However, since `base64` supports a limited set of characters, this project has the potential to run into some problems when storing data that contains characters that are not supported such as `{` and `}` when storing JSON data as a string (e.g. `'{"foo": "bar"}'`).

To address this issue, the `ciphertext.data` property is converted to `utf-8` and then to `base64` before being stored in the database. When the data is retrieved from the database, it is converted back to `utf-8` and then to a `Uint8Array` before being used.
