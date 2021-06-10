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

#import <PowerAuthCore/PowerAuthCoreActivationCode.h>

/**
 The `StartActivationParam` object contains parameters for first step of device activation.
 */
NS_SWIFT_NAME(StartActivationParam)
@interface PowerAuthCoreStartActivationParam : NSObject

/**
 Initialize object with provided activation code;
 */
- (nonnull instancetype) initWithActivationCode:(nullable PowerAuthCoreActivationCode*)activationCode;

/**
 Full, parsed activation code. The parameter is optional and may be nil
 in case of custom activation.
 */
@property (nonatomic, strong, nullable, readonly) PowerAuthCoreActivationCode * activationCode;

@end


/**
 The `StartActivationResult` object represents result from first
 step of the device activation.
 */
NS_SWIFT_NAME(StartActivationResult)
@interface PowerAuthCoreStartActivationResult : NSObject

/**
 Not available
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/**
 Device's public key, in Base64 format
 */
@property (nonatomic, strong, nonnull, readonly) NSString * devicePublicKey;

@end
