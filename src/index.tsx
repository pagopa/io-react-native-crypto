import { NativeModules, Platform } from "react-native";

/**
 * Error codes returned by the iOS module.
 */
type CryptoErrorCodesIOS =
  | "KEY_ALREADY_EXISTS"
  | "UNSUPPORTED_DEVICE"
  | "WRONG_KEY_CONFIGURATION"
  | "PUBLIC_KEY_NOT_FOUND"
  | "PUBLIC_KEY_DELETION_ERROR"
  | "KEYCHAIN_LOAD_FAILED"
  | "INVALID_UTF8_ENCODING"
  | "UNABLE_TO_SIGN"
  | "CERTIFICATE_CHAIN_VALIDATION_ERROR"
  | "THREADING_ERROR";

/**
 * Error codes returned by the Android side.
 */
type CryptoErrorCodesAndroid =
  | "KEY_ALREADY_EXISTS"
  | "UNSUPPORTED_DEVICE"
  | "WRONG_KEY_CONFIGURATION"
  | "PUBLIC_KEY_NOT_FOUND"
  | "PUBLIC_KEY_DELETION_ERROR"
  | "API_LEVEL_NOT_SUPPORTED"
  | "KEYSTORE_LOAD_FAILED"
  | "UNABLE_TO_SIGN"
  | "INVALID_UTF8_ENCODING"
  | "INVALID_SIGN_ALGORITHM"
  | "CERTIFICATE_CHAIN_VALIDATION_ERROR"
  | "GENERATE_SALT_ERROR"
  | "HASH_ERROR"
  | "UNSUPPORTED_ALGORITHM"
  | "UNSUPPORTED_CURVE"
  | "GENERATE_EPHEMERAL_KEY_PAIR_ERROR"
  | "SIGN_EPHEMERAL_ERROR"
  | "VERIFY_EPHEMERAL_ERROR"
  | "UNKNOWN_EXCEPTION";

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
  kty: "EC";
  crv: string;
  x: string;
  y: string;
};

/**
 * This is the JWK JSON type for the RSA keys.
 */
export type RSAKey = {
  kty: "RSA";
  alg: string;
  e: string;
  n: string;
};

/**
 * The Public Key type. It could be either an ECKey or an RSAKey.
 */
export type PublicKey = ECKey | RSAKey;

/**
 * Represents the status of certificate validation
 */
export enum CertificateValidationStatus {
  VALID = "VALID",
  INVALID_CHAIN_PATH = "INVALID_CHAIN_PATH", // Basic chain path validation failed (e.g., signature, structure)
  INVALID_TRUST_ANCHOR = "INVALID_TRUST_ANCHOR", // Provided trust anchor is invalid or does not match the chain
  EXPIRED = "CERTIFICATE_EXPIRED", // A certificate in the chain has expired
  NOT_YET_VALID = "CERTIFICATE_NOT_YET_VALID", // A certificate in the chain is not yet valid
  REVOKED = "CERTIFICATE_REVOKED", // Certificate explicitly marked as revoked in CRL
  CRL_FETCH_FAILED = "CRL_FETCH_FAILED", // Failed to download/access/validate a CRL (when CDPs were present)
  CRL_PARSE_FAILED = "CRL_PARSE_FAILED", // Failed to parse CRL content
  CRL_EXPIRED = "CRL_EXPIRED", // CRL used is expired
  CRL_SIGNATURE_INVALID = "CRL_SIGNATURE_INVALID", // Signature on CRL is invalid
  CRL_REQUIRED_BUT_MISSING_CDP = "CRL_REQUIRED_BUT_MISSING_CDP", // CRLs required but no CDP present
  VALIDATION_ERROR = "VALIDATION_ERROR", // General/unexpected error during validation
}

/**
 * Options for X.509 certificate validation
 */
export interface X509CertificateOptions {
  connectTimeout: number;
  readTimeout: number;
  requireCrl: boolean;
}

/**
 * Represents the result of certificate validation
 */
export interface CertificateValidationResult {
  /** Whether the certificate chain is valid */
  isValid: boolean;
  /** The specific validation status */
  validationStatus: CertificateValidationStatus;
  /** Error message in case validation failed */
  errorMessage: string;
}

const LINKING_ERROR =
  `The package '@pagopa/io-react-native-crypto' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: "" }) +
  "- You rebuilt the app after installing the package\n" +
  "- You are not using Expo Go\n";

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
 * Returns the public key in its JWK format using legacy encoding.
 *
 * - Uses standard Base64 encoding (includes padding and non-URL-safe characters)
 * - May include a leading zero byte in some fields (e.g., x, y, n, e)
 *
 * This method is kept for backward compatibility with older consumers that
 * expect this specific encoding. For a strict, interoperable format (RFC 7515),
 * use {@link getPublicKeyFixed} instead.
 *
 * If the key cannot be retrieved, the promise is rejected with an instance of {@link CryptoError}.
 *
 * @param keyTag - The key tag used to reference the key in secure storage.
 * @returns A promise that resolves to the JWK representation of the public key.
 */
export function getPublicKey(keyTag: string): Promise<PublicKey> {
  return IoReactNativeCrypto.getPublicKey(keyTag);
}

/**
 * This function returns the public key in its strict JWK-compliant format if it exists.
 *
 * Compared to {@link getPublicKey}, this version:
 * - Encodes coordinates (`x`, `y`) using Base64URL (RFC 7515), with no padding
 *
 * If it is not possible to retrieve the key, the promise is rejected providing an
 * instance of {@link CryptoError}.
 *
 * @param keyTag - The key tag used to reference the key in secure storage.
 * @returns a promise that resolves to the strict JWK representation of the public key.
 */
export function getPublicKeyFixed(keyTag: string): Promise<PublicKey> {
  return IoReactNativeCrypto.getPublicKeyFixed(keyTag);
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
 * @param message - the string message to sign.
 * @param keyTag - the string key tag used to reference the key in the key store.
 * @returns a promise that resolves to the Base64 string representation of the signature.
 */
export function sign(message: string, keyTag: string): Promise<string> {
  return IoReactNativeCrypto.signUTF8Text(message, keyTag);
}

/**
 * This function checks whether or not a key is backed by Strongbox on Android.
 *
 * If it is not possible to retrive the key, the promise is rejected providing an
 * instance of {@link CryptoError}.
 *
 * @param keyTag - the string key tag used to reference the key in the key store.
 * @returns a promise that resolves to true if the key is backed by Strongbox, false otherwise.
 */
export function isKeyStrongboxBacked(keyTag: string): Promise<boolean> {
  return IoReactNativeCrypto.isKeyStrongboxBacked(keyTag);
}

/**
 * Verifies a certificate chain against a trust anchor.
 *
 * @param certChainBase64 - Array of X.509 certificates in Base64 format, ordered from end-entity to issuer
 * @param trustAnchorBase64 - Trust anchor certificate in Base64 format
 * @param options - Options for certificate validation, including timeouts
 * @returns Promise resolving to validation result with detailed status
 */
export function verifyCertificateChain(
  certChainBase64: string[],
  trustAnchorBase64: string,
  options: X509CertificateOptions
): Promise<CertificateValidationResult> {
  return IoReactNativeCrypto.verifyCertificateChain(
    certChainBase64,
    trustAnchorBase64,
    options
  );
}

// ─── Soft-crypto primitives ───────────────────────────────────────────────

export type SupportedHashAlgorithm = "sha-256" | "sha-384" | "sha-512";
export type SupportedCurve = "P-256" | "P-384" | "P-521";

export type EphemeralPublicKeyJwk = {
  kty: "EC";
  crv: SupportedCurve;
  x: string;
  y: string;
};

export type EphemeralPrivateKeyJwk = EphemeralPublicKeyJwk & { d: string };

export type EphemeralKeyPair = {
  publicKeyJwk: EphemeralPublicKeyJwk;
  privateKeyJwk: EphemeralPrivateKeyJwk;
};

/**
 * Generates a random hex salt of exactly [length] characters.
 * Returns an empty string when length <= 0.
 */
export function generateSalt(length: number): Promise<string> {
  return IoReactNativeCrypto.generateSalt(length);
}

/**
 * Hashes [data] using the given [algorithm] (default: "sha-256").
 * Accepts a UTF-8 string or an ArrayBuffer.
 * Returns the raw hash bytes as a Uint8Array.
 */
export function digest(
  data: string | ArrayBuffer,
  algorithm: SupportedHashAlgorithm = "sha-256"
): Promise<Uint8Array> {
  let inputArg: string;
  let isBase64: boolean;

  if (typeof data === "string") {
    inputArg = data;
    isBase64 = false;
  } else {
    // Encode the raw bytes as Base64 so they survive the bridge
    const bytes = new Uint8Array(data);
    let binary = "";
    bytes.forEach((b) => (binary += String.fromCharCode(b)));
    inputArg = btoa(binary);
    isBase64 = true;
  }

  return IoReactNativeCrypto.hash(inputArg, isBase64, algorithm).then(
    (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
  );
}

/**
 * Generates an ephemeral ECDSA key pair (not hardware-backed) for the given curve.
 * Returns both keys in JWK format: { publicKeyJwk, privateKeyJwk }.
 */
export function generateEphemeralKeyPair(
  namedCurve: SupportedCurve
): Promise<EphemeralKeyPair> {
  return IoReactNativeCrypto.generateEphemeralKeyPair(namedCurve);
}

/**
 * Signs [data] (UTF-8) using the private key JWK and returns a
 * Base64URL-encoded IEEE P1363 signature (R‖S).
 */
export function signWithEphemeralKey(
  data: string,
  privateKeyJwk: object,
  namedCurve: SupportedCurve,
  hashAlgorithm: SupportedHashAlgorithm
): Promise<string> {
  return IoReactNativeCrypto.signWithEphemeralKey(
    data,
    privateKeyJwk,
    namedCurve,
    hashAlgorithm
  );
}

/**
 * Verifies a Base64URL IEEE P1363 [signature] against [data] (UTF-8)
 * using the public key JWK. Returns true when the signature is valid.
 */
export function verifyWithEphemeralKey(
  data: string,
  signatureBase64url: string,
  publicKeyJwk: object,
  namedCurve: SupportedCurve,
  hashAlgorithm: SupportedHashAlgorithm
): Promise<boolean> {
  return IoReactNativeCrypto.verifyWithEphemeralKey(
    data,
    signatureBase64url,
    publicKeyJwk,
    namedCurve,
    hashAlgorithm
  );
}

// ─── Algorithm helpers (mirrors the node:crypto reference implementation) ──

type GenerateKeyAlgorithm = { name: string; namedCurve: SupportedCurve };
type ImportKeyAlgorithm = { name: string; namedCurve: SupportedCurve };
type SignAlgorithm = { name: string; hash: { name: SupportedHashAlgorithm } };
type VerifyAlgorithm = { name: string; hash: { name: SupportedHashAlgorithm } };

export async function generateKeyPair(keyAlgorithm: GenerateKeyAlgorithm) {
  const { publicKeyJwk, privateKeyJwk } = await generateEphemeralKeyPair(
    keyAlgorithm.namedCurve
  );
  return { publicKey: publicKeyJwk, privateKey: privateKeyJwk };
}

export async function getSigner(
  privateKeyJWK: object,
  keyAlgorithm: ImportKeyAlgorithm,
  signAlgorithm: SignAlgorithm
) {
  const curve = keyAlgorithm.namedCurve;
  const hash = signAlgorithm.hash.name;
  return (data: string) => signWithEphemeralKey(data, privateKeyJWK, curve, hash);
}

export async function getVerifier(
  publicKeyJWK: object,
  keyAlgorithm: ImportKeyAlgorithm,
  verifyAlgorithm: VerifyAlgorithm
) {
  const curve = keyAlgorithm.namedCurve;
  const hash = verifyAlgorithm.hash.name;
  return (data: string, signatureBase64url: string) =>
    verifyWithEphemeralKey(data, signatureBase64url, publicKeyJWK, curve, hash);
}

export const ES256 = {
  alg: "ES256",
  _keyAlgorithm: { name: "ECDSA", namedCurve: "P-256" as SupportedCurve },
  _hashAlgorithm: {
    name: "ECDSA",
    hash: { name: "sha-256" as SupportedHashAlgorithm },
  },
  async generateKeyPair() {
    return generateKeyPair(ES256._keyAlgorithm);
  },
  async getSigner(privateKeyJWK: object) {
    return getSigner(privateKeyJWK, ES256._keyAlgorithm, ES256._hashAlgorithm);
  },
  async getVerifier(publicKeyJWK: object) {
    return getVerifier(publicKeyJWK, ES256._keyAlgorithm, ES256._hashAlgorithm);
  },
};

export const ES384 = {
  alg: "ES384",
  _keyAlgorithm: { name: "ECDSA", namedCurve: "P-384" as SupportedCurve },
  _hashAlgorithm: {
    name: "ECDSA",
    hash: { name: "sha-384" as SupportedHashAlgorithm },
  },
  async generateKeyPair() {
    return generateKeyPair(ES384._keyAlgorithm);
  },
  async getSigner(privateKeyJWK: object) {
    return getSigner(privateKeyJWK, ES384._keyAlgorithm, ES384._hashAlgorithm);
  },
  async getVerifier(publicKeyJWK: object) {
    return getVerifier(publicKeyJWK, ES384._keyAlgorithm, ES384._hashAlgorithm);
  },
};

export const ES512 = {
  alg: "ES512",
  _keyAlgorithm: { name: "ECDSA", namedCurve: "P-521" as SupportedCurve },
  _hashAlgorithm: {
    name: "ECDSA",
    hash: { name: "sha-512" as SupportedHashAlgorithm },
  },
  async generateKeyPair() {
    return generateKeyPair(ES512._keyAlgorithm);
  },
  async getSigner(privateKeyJWK: object) {
    return getSigner(privateKeyJWK, ES512._keyAlgorithm, ES512._hashAlgorithm);
  },
  async getVerifier(publicKeyJWK: object) {
    return getVerifier(publicKeyJWK, ES512._keyAlgorithm, ES512._hashAlgorithm);
  },
};
