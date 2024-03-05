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

RCT_EXTERN_METHOD(isKeyStrongboxBacked:(NSString*)keyTag
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(signUTF8Text:(NSString*)text withKeyTag:(NSString*)keyTag
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)


+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
