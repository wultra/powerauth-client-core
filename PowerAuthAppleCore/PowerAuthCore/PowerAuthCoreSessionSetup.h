
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

/**
 The PowerAuthCoreSessionSetup object defines unique constants required during the lifetime
 of the Session class.
 */
NS_SWIFT_NAME(SessionSetup)
@interface PowerAuthCoreSessionSetup : NSObject

/**
 Use designated initializer.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/// Initialize setup object with given parameters.
///
/// @param applicationKey Required APPLICATION_KEY constant.
/// @param applicationSecret Required APPLICATION_SECRET constant.
/// @param masterServerPublicKey Required master server public key constant.
/// @param externalEncryptionKey Optional external encryption key.
- (nonnull instancetype) initWithApplicationKey:(nonnull NSString*)applicationKey
                              applicationSecret:(nonnull NSString*)applicationSecret
                          masterServerPublicKey:(nonnull NSString*)masterServerPublicKey
                          externalEncryptionKey:(nullable NSData*)externalEncryptionKey;
/**
 Defines APPLICATION_KEY for the session.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * applicationKey;
/**
 Defines APPLICATION_SECRET for the session.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * applicationSecret;
/**
 The master server public key, in BASE64 format. It's strongly recommended to use
 different keys for the testing and production servers.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * masterServerPublicKey;
/**
 Optional external encryption key. If the data object size is equal to 16 bytes,
 then the key is considered as valid and will be used during the cryptographic operations.
 
 The additional encryption key is useful in  multibanking applications, where it allows the
 application to create chain of trusted PowerAuth activations. If the key is set, then the session will
 perform additional encryption / decryption operations when the signature keys are being used.
 
 The session implements a couple of simple protections against misuse of this feature and therefore
 once the session is activated with the EEK, then you have to use that EEK for all future cryptographic
 operations. The key is NOT serialized in the session's state and thus it's up to the application,
 how it manages the chain of multiple PowerAuth sessions.
 */
@property (nonatomic, strong, readonly, nullable) NSData * externalEncryptionKey;

@end
