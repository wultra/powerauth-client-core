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

#import "PowerAuthCoreActivationCodeUtil.h"
#import "PrivateInterfaces.h"

using namespace com::wultra::powerAuth;

@implementation PowerAuthCoreActivationCodeUtil

+ (BOOL) validateTypedCharacter:(UInt32)character
{
    return ActivationCodeUtil::validateTypedCharacter(character);
}

+ (UInt32) validateAndCorrectTypedCharacter:(UInt32)character
{
    return ActivationCodeUtil::validateAndCorrectTypedCharacter(character);
}

+ (BOOL) validateActivationCode:(NSString*)activationCode
{
    return ActivationCodeUtil::validateActivationCode(cc7::objc::CopyFromNSString(activationCode));
}

+ (BOOL) validateRecoveryCode:(nonnull NSString*)recoveryCode
{
    return ActivationCodeUtil::validateRecoveryCode(cc7::objc::CopyFromNSString(recoveryCode));
}

+ (BOOL) validateRecoveryPuk:(nonnull NSString*)recoveryPuk
{
    return ActivationCodeUtil::validateRecoveryPuk(cc7::objc::CopyFromNSString(recoveryPuk));
}

+ (PowerAuthCoreActivationCode*) parseFromActivationCode:(NSString*)activationCode
{
    auto cppActivationCode = cc7::objc::CopyFromNSString(activationCode);
    ActivationCode cppCode;
    if (ActivationCodeUtil::parseActivationCode(cppActivationCode, cppCode)) {
        return [[PowerAuthCoreActivationCode alloc] initWithStruct:cppCode];
    }
    return nil;
}

+ (PowerAuthCoreActivationCode*) parseFromRecoveryCode:(NSString *)recoveryCode
{
    auto cppRecoveryCode = cc7::objc::CopyFromNSString(recoveryCode);
    ActivationCode cppCode;
    if (ActivationCodeUtil::parseRecoveryCode(cppRecoveryCode, cppCode)) {
        return [[PowerAuthCoreActivationCode alloc] initWithStruct:cppCode];
    }
    return nil;
}

@end
