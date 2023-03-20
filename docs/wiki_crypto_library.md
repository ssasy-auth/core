# cryptographic libraries

## errors

Since this project works with a lot of cryptographic operations, it is important to have an understanding of what kind of errors can occur and how they can be handled. Below is a table of the errors that can occur, their names and how they can be handled. To begin with, there are two main types of errors that can occur:

- `CryptoKey` - These are errors related to the cryptographic key used ( see [mozilla documentation](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey) for more information).
- `DOMException` - These are errors related to cryptographic operation ( see [mozilla documentation](https://developer.mozilla.org/en-US/docs/Web/API/DOMException) for more information).

### CryptoKey Errors

| Error Name            | Error Code           | Description                                                                                |
| --------------------- | -------------------- | ------------------------------------------------------------------------------------------ |
| `KeyFormatError`      | `DataError`          | The key data is malformed or not in the expected format.                                   |
| `KeyUsageError`       | `InvalidAccessError` | The key is not allowed to be used for the requested operation.                             |
| `KeyOperationError`   | `OperationError`     | The requested key operation cannot be performed.                                           |

### DOMException Errors

| Error Name            | Error Code           | Description                                                                                |
| --------------------- | -------------------- | ------------------------------------------------------------------------------------------ |
| `DataError`           | `DataError`          | The provided data is not in the correct format or contains invalid data.                   |
| `InvalidAccessError`  | `InvalidAccessError` | The requested operation is not allowed by the user agent.                                  |
| `NotAllowedError`     | `NotAllowedError`    | The requested operation is not allowed in the current context.                             |
| `OperationError`      | `OperationError`     | The requested cryptographic operation cannot be performed.                                 |
| `SecurityError`       | `SecurityError`      | The requested operation is not allowed for security reasons.                               |
| `TypeMismatchError`   | `TypeMismatchError`  | The provided input parameter is of the wrong type or is not compatible with the operation. |
