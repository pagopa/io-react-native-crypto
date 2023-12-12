import type { ECKey, PublicKey } from '..';
import { JOSENotSupported } from './errors';

export const supportedAlgorithms = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
] as const;
export type SupportedAlgorithm = typeof supportedAlgorithms[number];

export const isAlgSupported = (alg: string): alg is SupportedAlgorithm =>
  (supportedAlgorithms as unknown as string[]).includes(alg.toUpperCase());

export const getKtyFromAlg = (alg: string) => {
  switch (alg.slice(0, 2)) {
    case 'RS':
    case 'PS':
      return 'RSA';
    case 'ES':
      return 'EC';
    default:
      throw new JOSENotSupported(
        'Unsupported "alg" value for a JSON Web Key Set'
      );
  }
};

export const getAlgFromKey = (publicKey: PublicKey): SupportedAlgorithm => {
  if (
    publicKey.kty === 'RSA' &&
    publicKey.alg &&
    isAlgSupported(publicKey.alg)
  ) {
    return publicKey.alg;
  } else if (publicKey.kty === 'EC') {
    return getAlgFromEllipticCurveKey(publicKey.crv);
  }

  throw new JOSENotSupported(
    `Unable to determine a supported algorithm for ${JSON.stringify(publicKey)}`
  );
};

const getAlgFromEllipticCurveKey = (crv: ECKey['crv']): SupportedAlgorithm => {
  switch (crv) {
    case 'P-256':
      return 'ES256';
    case 'P-384':
      return 'ES384';
    case 'P-512':
    case 'P-521': // https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/dev/src/Microsoft.IdentityModel.Tokens/JsonWebKeyECTypes.cs#L40
      return 'ES512';

    default:
      throw new JOSENotSupported(
        `Unsupported "crv" value for an elliptic curve key (${crv})`
      );
  }
};

// Coordinates length in bytes: bits/8
export const getCoordinateOctetLength = (alg: string) => {
  switch (alg.slice(2, 5)) {
    case '256':
      return 32;
    case '384':
      return 48;
    case '512':
      return 66;
    default:
      throw new JOSENotSupported(
        'Unsupported "alg" value for a JSON Web Key Set'
      );
  }
};
