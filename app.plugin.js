const {
  AndroidConfig,
  createRunOncePlugin,
  withInfoPlist,
} = requireConfigPlugins();

function requireConfigPlugins() {
  try {
    return require('expo/config-plugins');
  } catch (_) {
    return require(require.resolve('expo/config-plugins', {
      paths: [process.cwd()],
    }));
  }
}

const pkg = require('./package.json');

const DEFAULT_FACE_ID_MESSAGE =
  'This app uses Face ID to authorize the use of your cryptographic keys.';

/**
 * Expo config plugin for @pagopa/io-react-native-crypto.
 *
 * - iOS: adds `NSFaceIDUsageDescription` to the Info.plist, required when
 *   signing with keys generated with `requireAuthentication: true`.
 * - Android: adds the `android.permission.USE_BIOMETRIC` permission
 *   (also merged automatically from the library manifest).
 *
 * @param {import('expo/config').ExpoConfig} config
 * @param {{ faceIDPermission?: string } | undefined} props
 */
const withIoReactNativeCrypto = (config, props) => {
  config = withInfoPlist(config, (c) => {
    c.modResults.NSFaceIDUsageDescription =
      props?.faceIDPermission ??
      c.modResults.NSFaceIDUsageDescription ??
      DEFAULT_FACE_ID_MESSAGE;
    return c;
  });

  config = AndroidConfig.Permissions.withPermissions(config, [
    'android.permission.USE_BIOMETRIC',
  ]);

  return config;
};

module.exports = createRunOncePlugin(
  withIoReactNativeCrypto,
  pkg.name,
  pkg.version
);
