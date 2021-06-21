/*
 * Copyright 2021 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import <PowerAuthCore/PowerAuthCoreMacros.h>

@class PowerAuthCorePassword;

/**
 The `SignatureFactorkKeys` object contains all key encryption keys, required for the PowerAuth
 signature computation. You have to provide all keys involved into the signature computation,
 for selected combination of factors. For example, if you're going to compute signature for
 Possession + Biometry factor, then this object must contain valid possessionUnlockKey and biometryUnlockKey.
 */
NS_SWIFT_NAME(SignatureFactorkKeys)
@interface PowerAuthCoreSignatureFactorKeys : NSObject

/**
 Use designated initializer.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/// Initialize object with combination of factors.
///
/// @param possessionKey Key-encryption-key that protects possession factor.
/// @param biometryKey Key-encryption-key that protects biometry factor.
/// @param password User's password that protects knowledge factor.
- (nonnull instancetype) initWithPossessionKey:(nonnull NSData*)possessionKey
                                   biometryKey:(nullable NSData*)biometryKey
                                      password:(nullable PowerAuthCorePassword*)password;

/**
 The key-encryption-key required for signatures with "possession" factor.
 You have to provide a key based on the unique properties of the device.
 For example, WI-FI MAC address or UDID are a good sources for this
 key. You can use `PowerAuthCoreSession.normalizeSignatureUnlockKeyFromData()` method
 to convert arbitrary data into normalized key.
 
 You cannot use data object filled with zeros as a key.
 */
@property (nonatomic, strong, readonly, nonnull) NSData * possessionKey;
/**
 The key-encryption-key required for signatures with "biometry" factor. You should not
 use this key and factor, if device has no biometric engine available. You can use
 `PowerAuthCoreSession.generateSignatureUnlockKey()` for new key creation.
 
 You should store this key only to the storage, which can protect the
 key with using the biometry engine. For example, on iOS9+, you can use
 a keychain record, created with kSecAccessControlBiometry* flags.
 
 You cannot use data object filled with zeros as a key.
 */
@property (nonatomic, strong, readonly, nullable) NSData * biometryKey;
/**
 The password required for signatures with "knowledge" factor. The complexity
 of the password depends on the rules, defined by the application. You should
 never store the password to the permanent storage (like file system, or keychain)
 
 The `PowerAuthCoreSession` validates only the minimum lenght of the password and
 passwords shorter than 4 bytes will be rejected.
 */
@property (nonatomic, strong, readonly, nullable) PowerAuthCorePassword * password;

@end
