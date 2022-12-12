declare module 'io-react-native-crypto' {
  // function to generate a new key pair on the device
  export function generate(keyTag: string): Promise<PublicKey>;

  // function to retrieve a public key from the device
  export function getPublicKey(keyTag: string): Promise<PublicKey>;

  // function to sign a message with a key pair on the device
  export function sign(message: string, keyTag: string): Promise<string>;

  // function to delete a key pair on the device
  export function deleteKey(keyTag: string): Promise<boolean>;

  type CryptoErrorCodesIOS = "KEY_ALREADY_EXISTS"
    | "UNSUPPORTED_DEVICE"
    | "WRONG_KEY_CONFIGURATION"
    | "PUBLIC_KEY_NOT_FOUND"
    | "PUBLIC_KEY_DELETION_ERROR"
    | "KEYCHAIN_LOAD_FAILED"
    | "INVALID_UTF8_ENCODING"
    | "UNABLE_TO_SIGN"
    | "THREADING_ERROR"

  type CryptoErrorCodesAndroid = "KEY_ALREADY_EXISTS"
    | "UNSUPPORTED_DEVICE"
    | "WRONG_KEY_CONFIGURATION"
    | "PUBLIC_KEY_NOT_FOUND"
    | "PUBLIC_KEY_DELETION_ERROR"
    | "API_LEVEL_NOT_SUPPORTED"
    | "KEYSTORE_LOAD_FAILED"
    | "UNABLE_TO_SIGN"
    | "INVALID_UTF8_ENCODING"
    | "INVALID_SIGN_ALGORITHM"
    | "UNKNOWN_EXCEPTION"

  export type CryptoErrorCodes = CryptoErrorCodesAndroid | CryptoErrorCodesIOS

  export type ECKey = {
    kty: 'EC';
    crv: string;
    x: string;
    y: string;
  };

  export type RSAKey = {
    kty: 'RSA';
    alg: string;
    e: string;
    n: string;
  };

  export type PublicKey = ECKey | RSAKey;
}
