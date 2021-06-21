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

#import "PowerAuthCoreSignedData.h"
#import "PrivateInterfaces.h"

using namespace com::wultra::powerAuth;

@implementation PowerAuthCoreSignedData
{
    SignedData _signedData;
}

// Signing key

- (PowerAuthCoreSigningDataKey) signingDataKey
{
    return static_cast<PowerAuthCoreSigningDataKey>(_signedData.signingKey);
}

- (void) setSigningDataKey:(PowerAuthCoreSigningDataKey)signingDataKey
{
    _signedData.signingKey = static_cast<SignedData::SigningKey>(signingDataKey);
}


// Bytes setters and getters

- (NSData*) data
{
    return cc7::objc::CopyToNSData(_signedData.data);
}

- (void) setData:(NSData *)data
{
    _signedData.data = cc7::objc::CopyFromNSData(data);
}

- (NSData*) signature
{
    return cc7::objc::CopyToNSData(_signedData.signature);
}

- (void) setSignature:(NSData *)signature
{
    _signedData.signature = cc7::objc::CopyFromNSData(signature);
}

// Base64 setters and getters

- (NSString*) dataBase64
{
    return cc7::objc::CopyToNSString(_signedData.data.base64String());
}

- (void) setDataBase64:(NSString *)dataBase64
{
    _signedData.data.readFromBase64String(cc7::objc::CopyFromNSString(dataBase64));
}

- (NSString*) signatureBase64
{
    return cc7::objc::CopyToNSString(_signedData.signature.base64String());
}

- (void) setSignatureBase64:(NSString *)signatureBase64
{
    _signedData.signature.readFromBase64String(cc7::objc::CopyFromNSString(signatureBase64));
}

@end

@implementation PowerAuthCoreSignedData (Private)

- (instancetype) initWithStruct:(const com::wultra::powerAuth::SignedData &)structRef
{
    self = [super init];
    if (self) {
        _signedData = structRef;
    }
    return self;
}

- (const SignedData&) structRef
{
    return _signedData;
}

@end
