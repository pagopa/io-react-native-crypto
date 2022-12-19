# @pagopa/io-react-native-crypto

Module to generate and sign with crypto keys backed on device security hardware on react-native platform.

## Installation

```sh
yarn add @pagopa/io-react-native-crypto
```

## Usage

### Generate a key

```js
import { generate } from '@pagopa/io-react-native-crypto';

// ...

const result = await generate('PERSONAL_KEYTAG');
// result is the JWK of the generated public key
```

### Sign a message

```js
import { sign } from '@pagopa/io-react-native-crypto';

// ...

const result = await sign('A valid message to sign', 'PERSONAL_KEYTAG');
// result is the Base64 string representation of the signature.
```

### Retrieve the public key

```js
import { getPublicKey } from '@pagopa/io-react-native-crypto';

// ...

const result = await getPublicKey('PERSONAL_KEYTAG');
// result is the JWK of the generated public key, error if no key has been yet generated
```

### Delete the key

```js
import { deleteKey } from '@pagopa/io-react-native-crypto';

// ...

await deleteKey('PERSONAL_KEYTAG');
// no result is provided, error if no key has been found for the specified keytag
```

## Types

|  TypeName   | Description                                                                                                                                                  |
| :---------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
|    ECKey    | The JWK representation of an Elliptic Curve public key                                                                                                       |
|   RSAKey    | The JWK representation of an RSA public key                                                                                                                  |
|  PublicKey  | Type of the returned public key, may be either a RSAKey or a ECKey                                                                                           |
| CryptoError | This type defines the error returned by the generation of a key or signing a message it is composed by an error code and by an additional information object |

## Error Codes

|         TypeName          |  Platform   | Description                                                             |
| :-----------------------: | :---------: | ----------------------------------------------------------------------- |
|    KEY_ALREADY_EXISTS     | iOS/Android | The key you're trying to generate already exists                        |
|    UNSUPPORTED_DEVICE     | iOS/Android | Device doesn't support hardware backed keys                             |
|  WRONG_KEY_CONFIGURATION  | iOS/Android | The key configuration has not been correctly defined                    |
|   PUBLIC_KEY_NOT_FOUND    | iOS/Android | The public key is missing for a specific keyTag                         |
| PUBLIC_KEY_DELETION_ERROR | iOS/Android | An error occurred while deleting the public key                         |
|  API_LEVEL_NOT_SUPPORTED  |   Android   | The current Api Level doesn't support the hardware baked key generation |
|   KEYSTORE_LOAD_FAILED    |   Android   | It was not possible to load or store data on the Keystore               |
|   KEYCHAIN_LOAD_FAILED    |     iOS     | It was not possible to load or store data on the Keychain               |
|      UNABLE_TO_SIGN       | iOS/Android | It was not possible to sign the given string                            |
|   INVALID_UTF8_ENCODING   | iOS/Android | The encoded string doesn't respect the valid encoding format            |
|  INVALID_SIGN_ALGORITHM   |   Android   | The sign algorithm was not valid                                        |
|     UNKNOWN_EXCEPTION     |   Android   | Unexpected error                                                        |
|      THREADING_ERROR      |     iOS     | Unexpected error                                                        |

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
