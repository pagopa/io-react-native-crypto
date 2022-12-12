import { NativeModules, Platform } from 'react-native';

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

const LINKING_ERROR =
  `The package '@pagopa/io-react-native-crypto' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const IoReactNativeCrypto = NativeModules.IoReactNativeCrypto
  ? NativeModules.IoReactNativeCrypto
  : new Proxy(
    {},
    {
      get() {
        throw new Error(LINKING_ERROR);
      },
    }
  );

export function getPublicKey(keyTag: string): Promise<PublicKey> {
  return IoReactNativeCrypto.getPublicKey(keyTag);
}

export function generate(keyTag: string): Promise<PublicKey> {
  return IoReactNativeCrypto.generate(keyTag);
}

export function deletePublicKey(keyTag: string): Promise<PublicKey> {
  return IoReactNativeCrypto.deletePublicKey(keyTag);
}

export function sign(message: string, keyTag: string): Promise<string> {
  return IoReactNativeCrypto.signUTF8Text(message, keyTag);
}