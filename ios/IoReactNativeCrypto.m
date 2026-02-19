#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(IoReactNativeCrypto, NSObject)

RCT_EXTERN_METHOD(generate:(NSString*)keyTag
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deletePublicKey:(NSString*)keyTag
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKey:(NSString*)keyTag
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKeyFixed:(NSString*)keyTag
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(isKeyStrongboxBacked:(NSString*)keyTag
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(signUTF8Text:(NSString*)text withKeyTag:(NSString*)keyTag
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyCertificateChain:(NSArray *)certChainBase64
                  withTrustAnchorBase64:(NSString *)trustAnchorBase64
                  withOptions:(NSDictionary *)options
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateSalt:(nonnull NSNumber *)length
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(hash:(NSString *)data
                  withIsBase64Input:(BOOL)isBase64Input
                  withAlgorithm:(NSString *)algorithm
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateEphemeralKeyPair:(NSString *)namedCurve
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(signWithEphemeralKey:(NSString *)data
                  withPrivateKeyJwk:(NSDictionary *)privateKeyJwk
                  withNamedCurve:(NSString *)namedCurve
                  withHashAlgorithm:(NSString *)hashAlgorithm
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(verifyWithEphemeralKey:(NSString *)data
                  withSignatureBase64url:(NSString *)signatureBase64url
                  withPublicKeyJwk:(NSDictionary *)publicKeyJwk
                  withNamedCurve:(NSString *)namedCurve
                  withHashAlgorithm:(NSString *)hashAlgorithm
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
