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

#import "PowerAuthCoreValidateActivationResponse.h"
#import "PrivateInterfaces.h"

using namespace com::wultra::powerAuth;

@implementation PowerAuthCoreValidateActivationResponseParam

- (instancetype)initWithActivationId:(NSString*)activationId
                     serverPublicKey:(NSString*)serverPublicKey
                             ctrData:(NSString*)ctrData
                  activationRecovery:(PowerAuthCoreRecoveryData*)activationRecovery
{
    self = [super init];
    if (self) {
        _activationId = activationId;
        _serverPublicKey = serverPublicKey;
        _ctrData = ctrData;
        _activationRecovery = activationRecovery;
    }
    return self;
}

- (ActivationStep2Param) activationData
{
    ActivationStep2Param data;
    data.activationId               = cc7::objc::CopyFromNSString(_activationId);
    data.serverPublicKey            = cc7::objc::CopyFromNSString(_serverPublicKey);
    data.ctrData                    = cc7::objc::CopyFromNSString(_ctrData);
    if (_activationRecovery) {
        data.activationRecovery     = _activationRecovery.structRef;
    }
    return data;
}

@end

@implementation PowerAuthCoreValidateActivationResponseResult

- (instancetype) initWithStruct:(const com::wultra::powerAuth::ActivationStep2Result &)structRef
{
    self = [super init];
    if (self) {
        _activationFingerprint = cc7::objc::CopyToNSString(structRef.activationFingerprint);
    }
    return self;
}

@end
