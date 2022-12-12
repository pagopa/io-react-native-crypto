import { NativeModules, Platform } from 'react-native';

type ECKey = {
  kty: 'EC';
  crv: string;
  x: string;
  y: string;
};

type RSAKey = {
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