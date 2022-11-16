import { NativeModules, Platform } from 'react-native';

type ECKey = {
  alg: 'EC';
  crv: string;
  x: string;
  y: string;
};

type RSAKey = {
  alg: 'RSA';
  mod: string;
  exp: string;
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

export function multiply(a: number, b: number): Promise<number> {
  return IoReactNativeCrypto.multiply(a, b);
}

export function getPublicKey(keyTag: string): Promise<PublicKey> {
  return IoReactNativeCrypto.getPublicKey(keyTag);
}

export function generate(keyTag: string): Promise<PublicKey> {
  return IoReactNativeCrypto.generate(keyTag);
}
