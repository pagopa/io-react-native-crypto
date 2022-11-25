@objc(IoReactNativeCrypto)
class IoReactNativeCrypto: NSObject {
  private let keyConfig: KeyConfig = .ec
  
  @objc(multiply:withB:withResolver:withRejecter:)
  func multiply(
    a: Float, b: Float,
    resolve:RCTPromiseResolveBlock,
    reject:RCTPromiseRejectBlock
  ) -> Void {
    resolve(a*b)
  }
  
  @objc(generate:withResolver:withRejecter:)
  func generate(
    keyTag: String,
    resolve:RCTPromiseResolveBlock,
    reject:RCTPromiseRejectBlock
  ) -> Void {
    var privateKey: SecKey?
    var status: OSStatus
    // Erase all content and settings from emulator to start brand new.
    do {
      (privateKey, status) = try keyExists(keyTag: keyTag)
      guard status == errSecItemNotFound else {
        return // TODO:
      }
      privateKey = try generatePrivateKey(keyTag: keyTag)
    } catch {
      // TODO:
    }
    
    guard let privateKey = privateKey,
          let publicKey = SecKeyCopyPublicKey(privateKey) else {
      // TODO:
      return
    }
    
    let jwk = jwkRepresentation(publicKey)
    resolve(jwk)
  }
  
  @objc(deletePublicKey:withResolver:withRejecter:)
  func deletePublicKey(
    keyTag:String,
    resolve:RCTPromiseResolveBlock,
    reject:RCTPromiseRejectBlock
  ) -> OSStatus {
    let status = SecItemDelete(privateKeyKeychainQuery(keyTag: keyTag) as CFDictionary)
    if status != errSecSuccess {
      // TODO:
    }
    resolve(true)
    return status
  }
  
  @objc(getPublicKey:withResolver:withRejecter:)
  func getPublicKey(
    keyTag:String,
    resolve:RCTPromiseResolveBlock,
    reject:RCTPromiseRejectBlock
  ) {
    var privateKey: SecKey?
    var status: OSStatus
    do {
      (privateKey, status) = try keyExists(keyTag: keyTag)
      guard status == errSecSuccess else {
        return // TODO:
      }      
    } catch {
      // TODO:
    }
    
    guard let privateKey = privateKey,
          let publicKey = SecKeyCopyPublicKey(privateKey) else {
      // TODO:
      return
    }
    
    let jwk = jwkRepresentation(publicKey)
    resolve(jwk)
  }
  
  private func generatePrivateKey(keyTag: String) throws -> SecKey? {
    var error: Unmanaged<CFError>?
    
    // Key ACL
    guard let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .privateKeyUsage, // signing and verification
      &error
    ) else {
      throw error!.takeRetainedValue() as Error // TODO:
    }
    
    // Key Attributes
    let attributes: NSMutableDictionary = [
      kSecAttrKeyType: keyConfig.keyType(),
      kSecAttrKeySizeInBits: keyConfig.keySizeInBits(),
      kSecPrivateKeyAttrs: [
        kSecAttrIsPermanent: true,
        kSecAttrApplicationTag: keyTag.data(using: .utf8)!,
        kSecAttrAccessControl: access
      ]
    ]
    
    if keyConfig == .ec {
      attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
    }
    
    guard let key = SecKeyCreateRandomKey(attributes, &error) else {
      throw error!.takeRetainedValue() as Error // TODO:
    }
    return key
  }
  
  /// For an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string of 04 || X || Y
  /// https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation
  private func jwkRepresentation(_ publicKey: SecKey) -> [String:String]? {
    if let publicKeyExtneralRepresentation
        = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data {
      var publicKeyBytes: [UInt8] = []
      publicKeyBytes = Array(publicKeyExtneralRepresentation)
      
      // Sanity checks
      // 04 || X || Y -> "04" = 1, X = 32, Y = 32 -> 1+32+32 = 65
      guard publicKeyBytes.count == 65 else {
        return nil // TODO:
      }
      
      let xOctets = publicKeyBytes[1...32]
      let yOctets = publicKeyBytes[33...64]
      let y = String(decoding: Data(yOctets).base64EncodedData(), as: UTF8.self)
      let x = String(decoding: Data(xOctets).base64EncodedData(), as: UTF8.self)
      // https://www.rfc-editor.org/rfc/rfc7517
      // https://www.rfc-editor.org/rfc/rfc7518.html#page-6
      let jwk: [String:String]  = [
        "kty":"EC",
        "crv":"P-256",
        "x":"\(x)",
        "y":"\(y)"
      ]
      return jwk
    }
    return [:]
  }
  
  // https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_keychain
  private func keyExists(keyTag: String) throws -> (key: SecKey?, status: OSStatus) {
    let getQuery = privateKeyKeychainQuery(keyTag: keyTag)
    var item: CFTypeRef?
    let status = SecItemCopyMatching(getQuery as CFDictionary, &item)
    return (status == errSecSuccess ? (item as! SecKey) : nil, status)
  }
  
  private func privateKeyKeychainQuery(
    keyTag: String
  ) -> [String : Any] {
    return [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: keyTag,
      kSecAttrKeyType as String: keyConfig.keyType(),
      kSecReturnRef as String: true
    ]
  }
  
  /// On iOS we support only EC but we put all EC config in an enum
  /// to support future different key types.
  private enum KeyConfig: Int, CaseIterable {
    case ec
    
    func keyType() -> CFString {
      switch self {
      case .ec:
        return kSecAttrKeyTypeECSECPrimeRandom
      }
    }
    
    func keySizeInBits() -> Int {
      switch self {
      case .ec:
        return 256
      }
    }
    
    func keySignAlgorithm() -> SecKeyAlgorithm {
      switch self {
      case .ec:
        return .ecdsaSignatureMessageX962SHA256
      }
    }
  }
}

