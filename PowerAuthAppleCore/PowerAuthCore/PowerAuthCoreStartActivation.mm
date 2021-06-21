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

#import "PowerAuthCoreStartActivation.h"
#import "PrivateInterfaces.h"

using namespace com::wultra::powerAuth;

@implementation PowerAuthCoreStartActivationParam

- (instancetype) initWithActivationCode:(PowerAuthCoreActivationCode *)activationCode
{
    self = [super init];
    if (self) {
        _activationCode = activationCode;
    }
    return self;
}

- (ActivationStep1Param) activationData
{
    ActivationStep1Param data;
    data.activationCode         = cc7::objc::CopyFromNSString(_activationCode.activationCode);
    data.activationSignature    = cc7::objc::CopyFromNSString(_activationCode.activationSignature);
    return data;
}

@end


@implementation PowerAuthCoreStartActivationResult

- (instancetype) initWithStruct:(const ActivationStep1Result &)structRef
{
    self = [super init];
    if (self) {
        _devicePublicKey = cc7::objc::CopyToNSString(structRef.devicePublicKey);
    }
    return self;
}

@end
