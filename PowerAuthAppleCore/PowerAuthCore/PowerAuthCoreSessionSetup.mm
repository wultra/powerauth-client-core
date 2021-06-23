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

#import "PowerAuthCoreSessionSetup.h"
#import "PrivateInterfaces.h"

using namespace com::wultra::powerAuth;

@implementation PowerAuthCoreSessionSetup
{
    SessionSetup _sessionSetup;
}

- (nonnull instancetype) initWithApplicationKey:(nonnull NSString*)applicationKey
                              applicationSecret:(nonnull NSString*)applicationSecret
                          masterServerPublicKey:(nonnull NSString*)masterServerPublicKey
                          externalEncryptionKey:(nullable NSData*)externalEncryptionKey
{
    self = [super init];
    if (self) {
        _sessionSetup.applicationKey        = cc7::objc::CopyFromNSString(applicationKey);
        _sessionSetup.applicationSecret     = cc7::objc::CopyFromNSString(applicationSecret);
        _sessionSetup.masterServerPublicKey = cc7::objc::CopyFromNSString(masterServerPublicKey);
        _sessionSetup.externalEncryptionKey = cc7::objc::CopyFromNSData(externalEncryptionKey);
    }
    return self;
}

- (NSString*) applicationKey
{
    return cc7::objc::CopyToNSString(_sessionSetup.applicationKey);
}

- (NSString*) applicationSecret
{
    return cc7::objc::CopyToNSString(_sessionSetup.applicationSecret);
}

- (NSString*) masterServerPublicKey
{
    return cc7::objc::CopyToNSString(_sessionSetup.masterServerPublicKey);
}

- (NSData*) externalEncryptionKey
{
    return cc7::objc::CopyToNullableNSData(_sessionSetup.externalEncryptionKey);
}

@end


@implementation PowerAuthCoreSessionSetup (Private)

- (nonnull instancetype) initWithStruct:(const SessionSetup &)structRef
{
    self = [super init];
    if (self) {
        _sessionSetup = structRef;
    }
    return self;
}

- (const SessionSetup &) structRef
{
    return _sessionSetup;
}

@end
