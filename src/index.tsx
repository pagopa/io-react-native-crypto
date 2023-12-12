import { NativeModules, Platform } from 'react-native';
import { getCoordinateOctetLength } from './utils/algorithms';
import { getAlgFromKey } from './utils/algorithms';
/**
 * Error codes returned by the iOS module.
 */
type CryptoErrorCodesIOS =
  | 'KEY_ALREADY_EXISTS'
  | 'UNSUPPORTED_DEVICE'
  | 'WRONG_KEY_CONFIGURATION'
  | 'PUBLIC_KEY_NOT_FOUND'
  | 'PUBLIC_KEY_DELETION_ERROR'
  | 'KEYCHAIN_LOAD_FAILED'
  | 'INVALID_UTF8_ENCODING'
  | 'UNABLE_TO_SIGN'
  | 'THREADING_ERROR'
  | 'UNPACKING_BER_ENCODED_ASN1_ERROR';

/**
 * Error codes returned by the Android side.
 */
type CryptoErrorCodesAndroid =
  | 'KEY_ALREADY_EXISTS'
  | 'UNSUPPORTED_DEVICE'
  | 'WRONG_KEY_CONFIGURATION'
  | 'PUBLIC_KEY_NOT_FOUND'
  | 'PUBLIC_KEY_DELETION_ERROR'
  | 'API_LEVEL_NOT_SUPPORTED'
  | 'KEYSTORE_LOAD_FAILED'
  | 'UNABLE_TO_SIGN'
  | 'INVALID_UTF8_ENCODING'
  | 'INVALID_SIGN_ALGORITHM'
  | 'UNKNOWN_EXCEPTION'
  | 'UNPACKING_BER_ENCODED_ASN1_ERROR';

/**
 * All error codes that the module could return.
 */
export type CryptoErrorCodes = CryptoErrorCodesAndroid | CryptoErrorCodesIOS;

/**
 * Error type returned by a rejected promise.
 *
 * If additional error information are available,
 * they are stored in the {@link CryptoError["userInfo"]} field.
 */
export type CryptoError = {
  message: CryptoErrorCodes;
  userInfo: Record<string, string>;
};

/**
 * This is the JWK JSON type for the EC keys.
 */
export type ECKey = {
  kty: 'EC';
  crv: string;
  x: string;
  y: string;
};

/**
 * This is the JWK JSON type for the RSA keys.
 */
export type RSAKey = {
  kty: 'RSA';
  alg: string;
  e: string;
  n: string;
};

/**
 * The Public Key type. It could be either an ECKey or an RSAKey.
 */
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

/**
 * This function returns the public key in its JWK format if it exists.
 *
 * If it is not possible to retrive the key, the promise is rejected providing an
 * instance of {@link CryptoError}.
 *
 * @param keyTag - the string key tag used to reference the key in the key store.
 * @returns a promise that resolves to the JWK representation of the public key.
 */
export function getPublicKey(keyTag: string): Promise<PublicKey> {
  return IoReactNativeCrypto.getPublicKey(keyTag);
}

/**
 * This function generates a key pair and returns the public key
 * in its JWK format if succesfull.
 *
 * The key generation provides only keys that can be secured by hardware.
 *
 * - On iOS only Elliptic Curves (NIST P-256) are generated
 * - On Android there is a fallback mechanism where firstly
 *   an Elliptic Curve (NIST P-256) key is tried.
 *   If this key generation fails, an RSA 2048 key is tried.
 *
 * If there is already an associated key for the given `keyTag`,
 * the promise if rejected.
 *
 * If it is not possible to generate the key, the promise is rejected providing an
 * instance of {@link CryptoError}.
 *
 * @param keyTag - the string key tag used to save the key in the key store.
 * @returns a promise that resolves to the JWK representation of the public key.
 */
export function generate(keyTag: string): Promise<PublicKey> {
  return IoReactNativeCrypto.generate(keyTag);
}

/**
 * This function deletes the key pair associated with the provided `keyTag`.
 *
 * If there is not any key associated with the provided `keyTag` the promise
 * is successfully resolved.
 *
 * If it is not possible to delete the key pair, the promise is rejected providing an
 * instance of {@link CryptoError}.
 *
 * @param keyTag - the string key tag used to reference the key to delete from the key store.
 * @returns a promise that resolves when the key is successfully deleted.
 */
export function deleteKey(keyTag: string): Promise<void> {
  return IoReactNativeCrypto.deletePublicKey(keyTag);
}

/**
 * This function signs the provided `message`
 * with the private key associated with the provided `keyTag`.
 *
 * If it is not possible to sign, the promise is rejected providing an
 * instance of {@link CryptoError}.
 *
 * @param messge - the string message to sign.
 * @param keyTag - the string key tag used to reference the key in the key store.
 * @returns a promise that resolves to the Base64 string representation of the signature.
 */
export function sign(message: string, keyTag: string): Promise<string> {
  return IoReactNativeCrypto.signUTF8Text(message, keyTag);
}

/**
 * This function unpacks the provided `signature` in its ASN1 representation.
 *
 * @param signature - the Base64 string representation of the signature.
 * @param coordinateOctoLen - the length of the octet string representing the coordinates.
 * @returns a promise that resolves to the ASN1 representation of the signature.
 */
export function unpackBerEncodedASN1(
  signature: string,
  coordinateOctoLen: number
): Promise<string> {
  return IoReactNativeCrypto.unpackBerEncodedASN1(signature, coordinateOctoLen);
}

export { getCoordinateOctetLength, getAlgFromKey };
