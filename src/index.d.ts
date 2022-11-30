declare module 'io-react-native-crypto' {
  // function to generate a new key pair on the device
  export function generate(keyTag: string): Promise<PublicKey>;

  // function to retrieve a public key from the device
  export function getPublicKey(keyTag: string): Promise<PublicKey>;

  // function to sign a message with a key pair on the device
  export function sign(message: string, keyTag: string): Promise<string>;

  // function to delete a key pair on the device
  export function deleteKey(keyTag: string): Promise<boolean>;

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
}
