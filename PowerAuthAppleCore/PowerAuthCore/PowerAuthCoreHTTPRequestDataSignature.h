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
 The `HTTPRequestDataSignature` object contains result from HTTP request data signing
 operation.
 */
NS_SWIFT_NAME(HTTPRequestDataSignature)
@interface PowerAuthCoreHTTPRequestDataSignature : NSObject

/**
 Not available
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/**
 Version of PowerAuth protocol.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * version;
/**
 Activation identifier received during the activation process.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * activationId;
/**
 Application key copied from Session.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * applicationKey;
/**
 NONCE used for the signature calculation.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * nonce;
/**
 String representation of signature factor or combination of factors.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * factor;
/**
 Calculated signature
 */
@property (nonatomic, strong, nonnull, readonly) NSString * signature;
/**
 Contains a complete value for "X-PowerAuth-Authorization" HTTP header.
 */
@property (nonatomic, strong, nonnull, readonly) NSString * authHeaderValue;

@end
