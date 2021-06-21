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

#import "PowerAuthCoreSignatureFactorKeys.h"
#import "PrivateInterfaces.h"

using namespace com::wultra::powerAuth;

@implementation PowerAuthCoreSignatureFactorKeys
{
    SignatureUnlockKeys _keys;
}

- (instancetype) initWithPossessionKey:(NSData*)possessionKey
                           biometryKey:(NSData*)biometryKey
                              password:(PowerAuthCorePassword*)password
{
    self = [super init];
    if (self) {
        _keys.possessionUnlockKey   = cc7::objc::CopyFromNSData(possessionKey);
        _keys.biometryUnlockKey     = cc7::objc::CopyFromNSData(biometryKey);
        if (password) {
            _keys.userPassword      = password.structRef.passwordData();
        }
    }
    return self;
}

- (NSData*) possessionKey
{
    return cc7::objc::CopyToNSData(_keys.possessionUnlockKey);
}

- (NSData*) biometryKey
{
    return cc7::objc::CopyToNullableNSData(_keys.biometryUnlockKey);
}

- (PowerAuthCorePassword*) password
{
    if (!_keys.userPassword.empty()) {
        return [[PowerAuthCorePassword alloc] initWithStruct:_keys.userPassword];
    } else {
        return nil;
    }
}

@end

@implementation PowerAuthCoreSignatureFactorKeys (Private)

- (const SignatureUnlockKeys &) structRef
{
    return _keys;
}

- (SignatureFactor) signatureFactor
{
    SignatureFactor factor = 0;
    if (!_keys.possessionUnlockKey.empty()) {
        factor |= SF_Possession;
    }
    if (!_keys.biometryUnlockKey.empty()) {
        factor |= SF_Biometry;
    }
    if (!_keys.userPassword.empty()) {
        factor |= SF_Knowledge;
    }
    return factor;
}

@end
