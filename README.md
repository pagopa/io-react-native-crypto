# @pagopa/io-react-native-crypto

Module to generate and sign with crypto keys backed by device security hardware on React Native platforms.

## Installation

```sh
yarn add @pagopa/io-react-native-crypto
```

## Usage

### Generate a key

```ts
import { generate } from '@pagopa/io-react-native-crypto';

try {
  const result = await generate('PERSONAL_KEYTAG');
// result is the JWK of the generated public key
} catch (e) {
  const { message, userInfo } = e as CryptoError;
}
```

### Generate a key gated by user authentication (biometric / device PIN)

`generate` optionally accepts a `KeyAuthenticationPolicy`. With
`requireAuthentication: true`, **every** `sign` operation with the key requires
a fresh user authentication: biometric, with device credential
(PIN/pattern/password) fallback. The requirement is enforced by the OS key
store itself (iOS Secure Enclave access control / Android Keystore
user-authentication binding), not by an app-level check.

```ts
import { generate } from '@pagopa/io-react-native-crypto';

const result = await generate('PERSONAL_KEYTAG', {
  requireAuthentication: true,
  authenticationPrompt: {
    title: 'Confirm signing', // prompt title (iOS reason / Android title)
    subtitle: 'Authenticate to use the key', // Android only
    cancel: 'Cancel', // Android only, negative-button text
  },
  // invalidateOnEnrollmentChange: true, // see note below
});
```

When `options` is omitted (or `requireAuthentication` is `false`) the behavior
is exactly the same as before: the key is usable without any authentication.
`sign` keeps its usual signature; when the referenced key is gated the system
authentication prompt is presented automatically.

Per-platform behavior:

- **iOS**: the key is created in the Secure Enclave with the
  `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` protection class and a
  `userPresence` access control: Face ID / Touch ID with automatic "Enter
  Passcode" fallback. If the device passcode is removed, the key is deleted by
  the system. With `invalidateOnEnrollmentChange: true`, a biometric
  enrollment change invalidates only the biometric constraint and the key
  stays usable via passcode.
- **Android**: the key is generated with
  `setUserAuthenticationRequired(true)` and per-operation validity. On
  **API 30+** authentication is satisfied by a strong biometric **or** the
  device credential. On **API 23–29** crypto-bound authentication is
  **biometric-only** (no PIN fallback, an enrolled strong biometric is
  required to generate the key). `sign` presents an `androidx.biometric`
  `BiometricPrompt`, which requires the host activity to be a
  `FragmentActivity` (React Native's `ReactActivity` is one). With
  `invalidateOnEnrollmentChange: true`, an enrollment change makes the key
  **permanently** unusable. On devices where StrongBox does not support
  authentication-bound keys, generation automatically falls back to the TEE.

Requirements and caveats:

- A device PIN/passcode must be set, otherwise generation rejects with
  `PASSCODE_NOT_SET` (an unprotected key is never created).
- A canceled prompt rejects `sign` with `USER_CANCELED`.
- On iOS, add `NSFaceIDUsageDescription` to your app's `Info.plist`,
  otherwise Face ID authentication is not available for gated keys.
- The iOS Simulator does not present the authentication prompt for key
  usage — test on a real device.

### Sign a message

```ts
import { sign } from '@pagopa/io-react-native-crypto';

try {
  const signature = await sign('A valid message to sign', 'PERSONAL_KEYTAG');
// result is a base64-encoded string of the signature
} catch (e) {
  const { message, userInfo } = e as CryptoError;
}
```

### Retrieve the public key

#### `getPublicKeyFixed`

Returns the public key in **strict JWK-compliant** format.

- Base64URL encoding (URL-safe, no padding)
- Leading `0x00` sign-byte removed
- EC P-256 coordinates guaranteed to be **32 bytes**

```ts
import { getPublicKeyFixed } from '@pagopa/io-react-native-crypto';

const jwk = await getPublicKeyFixed('PERSONAL_KEYTAG');
```

#### `getPublicKey` (legacy)

Kept for backwards compatibility. Uses standard Base64 (with padding) and may include sign-bytes.

```ts
import { getPublicKey } from '@pagopa/io-react-native-crypto';

const jwkLegacy = await getPublicKey('PERSONAL_KEYTAG');
```

---

### Verify certificate chain

Validates an X.509 certificate chain (optionally with CRL checks).

```ts
import { verifyCertificateChain } from '@pagopa/io-react-native-crypto';

const result = await verifyCertificateChain(
  ['base64_leaf', 'base64_intermediate'],
  'base64_trust_anchor',
  {
    requireCrl: true,
    connectTimeout: 5000,
    readTimeout: 5000
  }
);

// result: CertificateValidationResult
// result.isValid === true            ↔  Certificate is trusted
// result.validationStatus === 'VALID'
```

<details>
<summary>CertificateValidationStatus codes</summary>

| Status Code                          | Meaning                                                    |
| ----------------------------------- | ---------------------------------------------------------- |
| `VALID`                             | Certificate chain is trusted                               |
| `INVALID_CHAIN_PATH`                | Basic path validation failed                               |
| `INVALID_TRUST_ANCHOR`              | Trust anchor mismatch                                      |
| `EXPIRED`                           | Certificate expired                                        |
| `NOT_YET_VALID`                     | Certificate is not yet valid                               |
| `REVOKED`                           | Certificate is listed as revoked in the CRL                |
| `CRL_REQUIRED_BUT_MISSING_CDP`      | CRL required but no CDP was present                        |
| `CRL_FETCH_FAILED`                  | Unable to download CRL                                     |
| `CRL_PARSE_FAILED`                  | Unable to parse downloaded CRL                             |
| `CRL_SIGNATURE_INVALID`             | CRL signature is invalid                                   |
| `CRL_EXPIRED`                       | CRL is expired                                             |
| `CHAIN_TOO_LONG`                    | Path length exceeds allowed max                            |
| `VALIDATION_ERROR`                 | Unexpected internal validation error                       |
</details>

If validation fails unexpectedly, a `CryptoError` is thrown with the code `CERTIFICATE_CHAIN_VALIDATION_ERROR`.

---

### Check if key is StrongBox-backed (Android only)

```ts
import { isKeyStrongboxBacked } from '@pagopa/io-react-native-crypto';

const backed = await isKeyStrongboxBacked('PERSONAL_KEYTAG');
console.log(backed ? 'StrongBox' : 'TEE');
```

---

### Delete the key

```ts
import { deleteKey } from '@pagopa/io-react-native-crypto';

await deleteKey('PERSONAL_KEYTAG');
```

---

## Types

| Type Name                 | Description                                                                 |
| ------------------------- | --------------------------------------------------------------------------- |
| `ECKey`                   | JWK representation of an Elliptic Curve public key                          |
| `RSAKey`                  | JWK representation of an RSA public key                                     |
| `PublicKey`               | Union of `ECKey` \| `RSAKey`                                                |
| `KeyAuthenticationPolicy` | Optional `generate` options gating key usage behind user authentication     |
| `CryptoError`             | Rejected promise error (contains `message` and `userInfo`)                  |
| `CertificateValidationStatus` | Enum of possible X.509 validation statuses                              |
| `CertificateValidationResult` | Returned object from `verifyCertificateChain`:<br/>`{ isValid: boolean, validationStatus: CertificateValidationStatus }` |

---

## Error Codes

|              TypeName              |  Platform   | Description                                                             |
|:----------------------------------:| :---------: |-------------------------------------------------------------------------|
|         `KEY_ALREADY_EXISTS`         | iOS/Android | The key you're trying to generate already exists                        |
|         `UNSUPPORTED_DEVICE`         | iOS/Android | Device doesn't support hardware backed keys or the requested method     |
|      `WRONG_KEY_CONFIGURATION`       | iOS/Android | The key configuration has not been correctly defined                    |
|        `PUBLIC_KEY_NOT_FOUND`        | iOS/Android | The public key is missing for a specific keyTag                         |
|     `PUBLIC_KEY_DELETION_ERROR`      | iOS/Android | An error occurred while deleting the public key                         |
|      `API_LEVEL_NOT_SUPPORTED`       |   Android   | The current API Level doesn't support the hardware baked key generation |
|        `KEYSTORE_LOAD_FAILED`        |   Android   | It was not possible to load or store data on the Keystore               |
|        `KEYCHAIN_LOAD_FAILED`        |     iOS     | It was not possible to load or store data on the Keychain               |
|           `UNABLE_TO_SIGN`           | iOS/Android | It was not possible to sign the given string                            |
|       `INVALID_UTF8_ENCODING`        | iOS/Android | The encoded string doesn't respect the valid encoding format            |
|       `INVALID_SIGN_ALGORITHM`       |   Android   | The sign algorithm was not valid                                        |
|         `UNKNOWN_EXCEPTION`          |   Android   | Unexpected error                                                        |
|          `THREADING_ERROR`           |     iOS     | Unexpected error                                                        |
| `CERTIFICATE_CHAIN_VALIDATION_ERROR` | iOS/Android | X.509 chain validation failed                                           |
|           `USER_CANCELED`            | iOS/Android | The user dismissed the authentication prompt of a gated key            |
|       `USER_NOT_AUTHENTICATED`       | iOS/Android | The key requires user authentication which was not performed           |
|            `AUTH_FAILED`             | iOS/Android | The user authentication attempt failed (or too many attempts/lockout)  |
|      `BIOMETRICS_NOT_AVAILABLE`      | iOS/Android | Biometric authentication is required but not available or not enrolled |
|          `PASSCODE_NOT_SET`          | iOS/Android | The device has no PIN/pattern/passcode set                             |

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
