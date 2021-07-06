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

@class PowerAuthCoreECPublicKey;

/**
 The `PowerAuthCoreCryptoUtils` class provides a several general cryptographic primitives
 required in our other open source libraries.
 */
NS_SWIFT_NAME(CryptoUtils)
@interface PowerAuthCoreCryptoUtils : NSObject

/**
 Use designated initializer.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/**
 Validates ECDSA signature for given data and EC public key.
 */
+ (BOOL) ecdsaValidateSignature:(nonnull NSData*)signature
                        forData:(nonnull NSData*)data
                   forPublicKey:(nonnull PowerAuthCoreECPublicKey*)publicKey
                          error:(NSError * _Nullable * _Nullable)error
                   NS_SWIFT_NAME(ecdsaValidateSignature(signature:for:publicKey:));

/**
 Computes SHA-256 from given data.
 */
+ (nullable NSData*) hashSha256:(nonnull NSData*)data
                          error:(NSError * _Nullable * _Nullable)error
                   NS_SWIFT_NAME(hashSha256(data:));

/**
 Computes HMAC-SHA-256 for given data and key. Returns nil in case that underlying
 implementation fail.
 */
+ (nullable NSData*) hmacSha256:(nonnull NSData*)data
                           key:(nonnull NSData*)key
                         error:(NSError * _Nullable * _Nullable)error
                  NS_SWIFT_NAME(hmacSha256(data:key:));

/**
 Computes HMAC-SHA-256 with requested length for given data and key. Returns nil in
 case that underlying implementation fail.
 */
+ (nullable NSData*) hmacSha256:(nonnull NSData*)data
                            key:(nonnull NSData*)key
                         length:(NSInteger)length
                          error:(NSError * _Nullable * _Nullable)error
                   NS_SWIFT_NAME(hmacSha256(data:key:length:));

/**
 Generates a required amount of random bytes. Returns nil in case that 
 underlying random generator is broken.
 */
+ (nullable NSData*) randomBytes:(NSInteger)count
                           error:(NSError * _Nullable * _Nullable)error
                    NS_SWIFT_NAME(randomBytes(count:));

@end


/**
 The `PowerAuthCoreECPublicKey` is an object representing public key in cryptography
 based on elliptic curves.
 */
NS_SWIFT_NAME(ECPublicKey)
@interface PowerAuthCoreECPublicKey: NSObject

/**
 Initializes object with EC public key data.
 Returns nil if invalid data is provided.
 */
- (nullable id) initWithData:(nonnull NSData*)publicKeyData;

@end
