/**
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
 The `ActivationCode` object contains parsed components from user-provided activation, or recovery
 code. You can use methods from `ActivationCodeUtil` class to fill this object with valid data.
 */
NS_SWIFT_NAME(ActivationCode)
@interface PowerAuthCoreActivationCode : NSObject

/**
 Not available.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/**
 Construct object with provided activation code and optional activation signature. Be aware, that valus
 provided to the constructor should be already validated by `ActivationCodeUtil` class.
 */
- (nonnull instancetype) initWithActivationCode:(nonnull NSString*)activationCode
                            activationSignature:(nullable NSString*)activationSignature;

/**
 If object is constructed from an activation code, then property contains just a code, without a signature part.
 If object is constructed from a recovery code, then property contains just a code, without an optional "R:" prefix.
 */
@property (nonnull, nonatomic, strong, readonly) NSString * activationCode;
/**
 Signature calculated from activationCode. The value is typically optional for cases,
 when the user re-typed activation code manually.
 
 If object is constructed from a recovery code, then the activation signature part is always empty.
 */
@property (nullable, nonatomic, strong, readonly) NSString * activationSignature;

@end
