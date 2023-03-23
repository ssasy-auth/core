# `ssasy` architecture

## constraints

This projects is constructed with the following constraints in mind:

- the cryptographic algorithms used in this project are secure
- the conversations between the claimant and the verifier happen over secure channels (e.g. https). This is in line with the constrains of the [WebCrypto API](../technology/cryptography.md#webcrypto-api) which is used to implement the cryptographic operations.
- trusted third parties are not a viable option for this project (e.g. no certificate authorities).

## project structure

At a high level, the project is structured as follows:

- `tests/` - contains the tests for the project
- `src/` - project source code
  - `config/` - project configuration
  - `interfaces/` - typescript interfaces
  - `modules/` - the modules that make up the project
    - `challenge-mod.ts` - creating and verifying challenges
    - `crypto-mod.ts` - cryptographic operations
    - `encoder-mod.ts` - encoding and decoding data
    - `key-mod.ts` - key operations
    - `indext.ts` - entry point for the module
  - `utils/` - contains utility or plugins that are used by the project
  - `wallet.ts` - contains the wallet class for the project
  - `index.ts` - contains the entry point for the project

## utils

The utils folder contains the wrappers for the [WebCrypto API](../technology/cryptography.md#webcrypto-api) and the [buffer library](../technology/cryptography.md#buffer-library). These wrappers act as a layer of abstraction between the project and the underlying dependencies. This allows the project to be more flexible in the future if the underlying dependencies change. This also allows the project to swap out the underlying dependencies depending on the environment (e.g. browser vs node) which is the case for the WebCrypto API.

## modules

The modules folder contains the core logic of the project. Each module is responsible for a specific task:

- `key-mod.ts` - this is the module that is responsible for all key operations. This includes generating symmetric and asymmetric keys as well as exporting and importing keys. This is also the only module that does not depend on any other module.
- `crypto-mod.ts` - this is the module that is responsible for all cryptographic operations - generating random numbers (nonces), encryption, decryption and hashing. This module depends on the `key-mod.ts` module for encrypting and decrypting payloads with passphrases (strings) as well as for encrypting and decrypting payloads with keys.
- `challenge-mod.ts` - this is the module that is responsible for generating and verifying challenges. This module depends on the `crypto-mod.ts` module for a number of cryptographic operations (e.g. generating random numbers, hashing, etc.).
- `encoder-mod.ts` - this is the module that is responsible for encoding and decoding data. This is necessary because the underlying dependencies (e.g. WebCrypto API) only work with buffers which means that the data is converted to a buffer when in-use and then converted back to a string when it is no longer in-use.

## wallet

The `wallet` class provides a means for `claimants` and `verifiers` to interact during the challenge-response ritual within the registration and login processes. This includes:

- generating a challenge
- solving a challenge
- verifying a solution

These operations can also be performed by using the modules directly, but the `wallet` class provides an abstraction that makes it easier to use the modules in a more user-friendly way for `claimant` and `verifier` developers.
