# `ssasy` architecture

This document describes the design and architecture of the `ssasy` project.

- [cryptographic keys](./crypto-keys.md)
- [cryptographic operations](./crypto-operations.md)
- [user authentication modules](./auth-modules.md)
- [user authentication processes](./auth-processes.md)

## assumptions

This project assumes the following:

- the underlying cryptographic algorithms are secure
- the underlying browser and the operating system are secure
- the underlying [WebCrypto API](../technology/cryptography.md#webcrypto-api) is secure
- the communication channels are secure (e.g. https)
