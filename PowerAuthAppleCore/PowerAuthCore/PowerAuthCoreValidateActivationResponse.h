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

#import <PowerAuthCore/PowerAuthCoreRecoveryData.h>

/**
 The `ValidateActivationResponseParam` contains parameters for second step of
 device activation
 */
NS_SWIFT_NAME(ValidateActivationResponseParam)
@interface PowerAuthCoreValidateActivationResponseParam : NSObject

/**
 Not available.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/// Initialize object with given parameters.
/// @param activationId Activation ID received from the server. Should not be null.
/// @param serverPublicKey Server's public key in Base64 format. Should not be null.
/// @param ctrData Initial value for hash-based counter. Should not be null.
/// @param activationRecovery Optional activation recovery data.
- (nonnull instancetype)initWithActivationId:(nullable NSString*)activationId
                             serverPublicKey:(nullable NSString*)serverPublicKey
                                     ctrData:(nullable NSString*)ctrData
                          activationRecovery:(nullable PowerAuthCoreRecoveryData*)activationRecovery;

/**
 Real Activation ID received from server.
 */
@property (nonatomic, strong, nullable, readonly) NSString * activationId;
/**
 Server's public key, in Base64 format.
 */
@property (nonatomic, strong, nullable, readonly) NSString * serverPublicKey;
/**
 Initial value for hash-based counter.
 */
@property (nonatomic, strong, nullable, readonly) NSString * ctrData;
/**
 If configured on the server, contains recovery data received from the server.
 */
@property (nonatomic, strong, nullable, readonly) PowerAuthCoreRecoveryData * activationRecovery;

@end


/**
 The `ValidateActivationResponseResult` object represent result from 2nd
 step of activation.
 */
NS_SWIFT_NAME(ValidateActivationResponseResult)
@interface PowerAuthCoreValidateActivationResponseResult : NSObject

/**
 Not available.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/**
 Short, human readable string, calculated from device's public key.
 You can display this code to the UI and user can confirm visually
 if the code is the same on both, server & client sides. This feature
 must be supported on the server's side of the activation flow.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * activationFingerprint;

@end

