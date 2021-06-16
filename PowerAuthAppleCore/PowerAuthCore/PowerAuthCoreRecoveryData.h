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
 The `RecoveryData` object contains information about recovery code and PUK, created
 during the activation process.
 */
NS_SWIFT_NAME(RecoveryData)
@interface PowerAuthCoreRecoveryData : NSObject

/**
 Not available
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/**
 Initialize object with given recovery code and PUK.
 */
- (nonnull instancetype)initWithRecoveryCode:(nonnull NSString*)recoveryCode
										 puk:(nonnull NSString*)puk;

/**
 Contains recovery code.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * recoveryCode;
/**
 Contains PUK, valid with recovery code.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * puk;

@end
