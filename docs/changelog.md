# Changelog

> Only notable changes are documented here.

## `2.2.0` - Wallet Class

- [breaking] Enforces SSASy URI format for all SSASy resources that are passed to (and returned from) the `Wallet` class.
- [breaking] Renames wallet methods; `sign()` -> `generateSignature()`, `verify()` -> `verifySignature()`, `solveChallenge()` -> `generateChallengeResponse()`, `verifyChallenge()` -> `verifyChallengeResponse()`.

### Migrating from `2.1.x` to `2.2.0`

- Update all SSASy resources (i.e. keys and isgnatures) to use the SSASy URI format (see [`SerializerModule`](../src/modules/serializer-mod.ts) for more details).

## `2.0.0` - SSASy URIs

- [feature] Introduces URIs for SSASy resources (i.e. keys, ciphertexts, challenges) which are used to represent resources in a standardised way that is easy to store, share and process (see [`SerializerModule`](../src/modules/serializer-mod.ts) for more details).
- [breaking] Refactors the `EncoderModule` into a `SerializerModule` which describes, more accurately, what the module does.
- [paatch] Renames `ProcessedKey` to `SecureContextKey` to better describe what the type represents, which is a WebCrypto key that is used in a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts).

### Migrating from `1.9.6` to `2.0.0`

- Refactor all code that uses the `EncoderModule` to use the `SerializerModule` instead (see [`SerializerModule`](../src/modules/serializer-mod.ts) for more details)
