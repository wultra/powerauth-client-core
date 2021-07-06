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

#import <cc7/objc/ObjcHelper.h>     // must be first included
#import <PowerAuthCore/PowerAuthCoreCryptoUtils.h>
#import "PrivateFunctions.h"

#include "CryptoUtils.h"            // Accessing private header; will be fixed by moving crypto to cc7


using namespace com::wultra::powerAuth;

#pragma mark - Private interfaces -

@interface PowerAuthCoreECPublicKey (Private)
@property (nonatomic, readonly) EC_KEY * ecKeyRef;
@end



#pragma mark -

@implementation PowerAuthCoreCryptoUtils

+ (BOOL) ecdsaValidateSignature:(NSData *)signature
                        forData:(NSData *)data
                   forPublicKey:(PowerAuthCoreECPublicKey *)publicKey
                          error:(NSError **)error
{
    if (!publicKey || !data || !signature) {
        if (error) {
            *error = PowerAuthCoreMakeError(PowerAuthCoreErrorCode_WrongParam, nil);
        }
        return NO;
    }
    auto cpp_data = cc7::objc::CopyFromNSData(data);
    auto cpp_signature = cc7::objc::CopyFromNSData(signature);
    return (BOOL) crypto::ECDSA_ValidateSignature(cpp_data, cpp_signature, publicKey.ecKeyRef);
}


+ (NSData*) hashSha256:(NSData *)data
                 error:(NSError **)error
{
    if (!data) {
        if (error) {
            *error = PowerAuthCoreMakeError(PowerAuthCoreErrorCode_WrongParam, nil);
        }
        return nil;
    }
    auto cpp_data = cc7::objc::CopyFromNSData(data);
    auto cpp_hash = crypto::SHA256(cpp_data);
    return cc7::objc::CopyToNSData(cpp_hash);
}


+ (NSData*) hmacSha256:(NSData *)data
                   key:(NSData *)key
                 error:(NSError **)error
{
    if (!data || !key) {
        if (error) {
            *error = PowerAuthCoreMakeError(PowerAuthCoreErrorCode_WrongParam, nil);
        }
        return nil;
    }
    auto result = crypto::HMAC_SHA256(cc7::objc::CopyFromNSData(data), cc7::objc::CopyFromNSData(key), 0);
    if (result.empty()) {
        if (error) {
            *error = PowerAuthCoreMakeError(PowerAuthCoreErrorCode_GeneralFailure, @"HMAC_SHA256 calculation failed");
        }
        return nil;
    }
    return cc7::objc::CopyToNSData(result);
}


+ (NSData*) hmacSha256:(NSData *)data
                   key:(NSData *)key
                length:(NSInteger)length
                 error:(NSError **)error
{
    if (!data || !key) {
        if (error) {
            *error = PowerAuthCoreMakeError(PowerAuthCoreErrorCode_WrongParam, nil);
        }
        return nil;
    }
    if (length <= 0) {
        if (error) {
            *error = PowerAuthCoreMakeError(PowerAuthCoreErrorCode_WrongParam, @"length must be greater than 0");
        }
        return nil;
    }
    auto result = crypto::HMAC_SHA256(cc7::objc::CopyFromNSData(data), cc7::objc::CopyFromNSData(key), length);
    if (result.empty()) {
        if (error) {
            *error = PowerAuthCoreMakeError(PowerAuthCoreErrorCode_GeneralFailure, @"HMAC_SHA256 calculation failed");
        }
        return nil;
    }
    return cc7::objc::CopyToNSData(result);
}


+ (NSData*) randomBytes:(NSInteger)count
                  error:(NSError **)error
{
    if (count <= 0) {
        if (error) {
            *error = PowerAuthCoreMakeError(PowerAuthCoreErrorCode_WrongParam, @"count must be greater than 0");
        }
        return nil;
    }
    auto result = crypto::GetRandomData(count, true);
    if (result.empty()) {
        if (error) {
            *error = PowerAuthCoreMakeError(PowerAuthCoreErrorCode_GeneralFailure, @"Failed to generate random bytes");
        }
        return nil;
    }
    return cc7::objc::CopyToNSData(result);
}

@end



#pragma mark -

@implementation PowerAuthCoreECPublicKey
{
    EC_KEY * _key;
}

#pragma mark - Init & Dealloc

- (void) dealloc
{
    EC_KEY_free(_key);
    _key = nullptr;
}

- (id) initWithData:(NSData *)publicKeyData
{
    self = [super init];
    if (self) {
        _key = crypto::ECC_ImportPublicKey(nullptr, cc7::objc::CopyFromNSData(publicKeyData));
        if (!_key) {
            return nil;
        }
    }
    return self;
}

#pragma mark - Getters

- (EC_KEY*) ecKeyRef
{
    return _key;
}

@end
