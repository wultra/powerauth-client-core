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

#include <PowerAuth/ECIES.h>
#include <cc7/objc/ObjcHelper.h>

#import <PowerAuthCore/PowerAuthCoreEciesEncryptor.h>
#import <PowerAuthCore/PowerAuthCoreSession.h>
#import "PrivateFunctions.h"
#import "PrivateInterfaces.h"

using namespace com::wultra::powerAuth;


#pragma mark - ECIES Encryptor implementation -

@implementation PowerAuthCoreEciesEncryptor
{
    ECIESEncryptor _encryptor;
}


#pragma mark Initialization

- (id) initWithObject:(const ECIESEncryptor &)objectRef
{
    self = [super init];
    if (self) {
        _encryptor = objectRef;
    }
    return self;
}

- (id) initWithPublicKey:(NSData*)publicKey
             sharedInfo1:(NSData*)sharedInfo1
             sharedInfo2:(NSData*)sharedInfo2
{
    auto encryptor = ECIESEncryptor(cc7::objc::CopyFromNSData(publicKey), cc7::objc::CopyFromNSData(sharedInfo1), cc7::objc::CopyFromNSData(sharedInfo2));
    return [self initWithObject: encryptor];
}

- (nullable PowerAuthCoreEciesEncryptor*) copyForDecryption
{
    if (_encryptor.canDecryptResponse()) {
        PowerAuthCoreEciesEncryptor * decryptor = [[PowerAuthCoreEciesEncryptor alloc] initWithObject:ECIESEncryptor(_encryptor.envelopeKey(), _encryptor.ivForDecryption(), _encryptor.sharedInfo2())];
        if (decryptor) {
            decryptor->_associatedMetaData = _associatedMetaData;
        }
        return decryptor;
    }
    return nil;
}

#pragma mark Setters & Getters

- (ECIESEncryptor &) encryptorRef
{
    return _encryptor;
}

- (NSData*) publicKey
{
    return cc7::objc::CopyToNullableNSData(_encryptor.publicKey());
}

- (void) setSharedInfo2:(NSData *)sharedInfo2
{
    _encryptor.setSharedInfo2(cc7::objc::CopyFromNSData(sharedInfo2));
}

- (NSData*) sharedInfo2
{
    return cc7::objc::CopyToNullableNSData(_encryptor.sharedInfo2());
}

- (BOOL) canEncryptRequest
{
    return _encryptor.canEncryptRequest();
}

- (BOOL) canDecryptResponse
{
    return _encryptor.canDecryptResponse();
}

#pragma mark - Encrypt & Decrypt

- (nullable PowerAuthCoreEciesCryptogram *) encryptRequest:(nullable NSData *)data
                                                     error:(NSError * _Nullable * _Nullable)error
{
    PowerAuthCoreEciesCryptogram * cryptogram = [[PowerAuthCoreEciesCryptogram alloc] init];
    auto ec = _encryptor.encryptRequest(cc7::objc::CopyFromNSData(data), cryptogram.cryptogramRef);
    if (ec != EC_Ok && error != nil) {
        *error = PowerAuthCoreMakeError(ec, nil);
    }
    return ec == EC_Ok ? cryptogram : nil;
}

- (nullable NSData *) decryptResponse:(nonnull PowerAuthCoreEciesCryptogram *)cryptogram
                                error:(NSError * _Nullable * _Nullable)error
{
    cc7::ByteArray data;
    auto ec = _encryptor.decryptResponse(cryptogram.cryptogramRef, data);
    if (ec != EC_Ok && error != nil) {
        *error = PowerAuthCoreMakeError(ec, nil);
    }
    return ec == EC_Ok ? cc7::objc::CopyToNSData(data) : nil;
}

- (BOOL) encryptRequest:(NSData *)data
             completion:(void (NS_NOESCAPE ^)(PowerAuthCoreEciesCryptogram * cryptogram, PowerAuthCoreEciesEncryptor * decryptor, NSError * error))completion
{
    PowerAuthCoreEciesEncryptor * decryptor;
    PowerAuthCoreEciesCryptogram * cryptogram;
    NSError * error = nil;
    @synchronized (self) {
        cryptogram = [self encryptRequest:data error:&error];
        decryptor = cryptogram ? [self copyForDecryption] : nil;
    }
    if (completion) {
        completion(cryptogram, decryptor, error);
    }
    return cryptogram != nil;
}

@end




#pragma mark - ECIES Cryptogram implementation -

@implementation PowerAuthCoreEciesCryptogram
{
    ECIESCryptogram _c;
}

- (ECIESCryptogram &) cryptogramRef
{
    return _c;
}

// NSData setters and getters

- (void) setBody:(NSData *)body
{
    _c.body = cc7::objc::CopyFromNSData(body);
}
- (NSData*) body
{
    return cc7::objc::CopyToNullableNSData(_c.body);
}

- (void) setMac:(NSData *)mac
{
    _c.mac = cc7::objc::CopyFromNSData(mac);
}
- (NSData*) mac
{
    return cc7::objc::CopyToNullableNSData(_c.mac);
}

- (void) setKey:(NSData *)key
{
    _c.key = cc7::objc::CopyFromNSData(key);
}
- (NSData*) key
{
    return cc7::objc::CopyToNullableNSData(_c.key);
}

- (void) setNonce:(NSData *)nonce
{
    _c.nonce = cc7::objc::CopyFromNSData(nonce);
}
- (NSData*) nonce
{
    return cc7::objc::CopyToNullableNSData(_c.nonce);
}


// Base64 setters and getters

- (void) setBodyBase64:(NSString *)bodyBase64
{
    _c.body.readFromBase64String(cc7::objc::CopyFromNSString(bodyBase64));
}
- (NSString*) bodyBase64
{
    return cc7::objc::CopyToNullableNSString(_c.body.base64String());
}

- (void) setMacBase64:(NSString *)macBase64
{
    _c.mac.readFromBase64String(cc7::objc::CopyFromNSString(macBase64));
}
- (NSString*) macBase64
{
    return cc7::objc::CopyToNullableNSString(_c.mac.base64String());
}

- (void) setKeyBase64:(NSString *)keyBase64
{
    _c.key.readFromBase64String(cc7::objc::CopyFromNSString(keyBase64));
}
- (NSString*) keyBase64
{
    return cc7::objc::CopyToNullableNSString(_c.key.base64String());
}

- (void) setNonceBase64:(NSString *)nonceBase64
{
    _c.nonce.readFromBase64String(cc7::objc::CopyFromNSString(nonceBase64));
}
- (NSString*) nonceBase64
{
    return cc7::objc::CopyToNullableNSString(_c.nonce.base64String());
}

@end


#pragma mark - ECIES metadata -

@implementation PowerAuthCoreEciesMetaData

- (instancetype) initWithApplicationKey:(NSString*)applicationKey
                   activationIdentifier:(NSString*)activationIdentifier
{
    self = [super init];
    if (self) {
        _applicationKey = applicationKey;
        _activationIdentifier = activationIdentifier;
    }
    return self;
}

- (NSString*) httpHeaderKey
{
    return @"X-PowerAuth-Encryption";
}

- (NSString*) httpHeaderValue
{
    NSString * protocolVersion = [PowerAuthCoreSession maxSupportedHttpProtocolVersion:PowerAuthCoreProtocolVersion_NA];
    NSString * value = [[[[@"PowerAuth version=\""
                         stringByAppendingString:protocolVersion]
                        stringByAppendingString:@"\", application_key=\""]
                         stringByAppendingString:_applicationKey]
                        stringByAppendingString:@"\""];
    if (_activationIdentifier) {
        return [[[value stringByAppendingString:@", activation_id=\""]
                 stringByAppendingString:_activationIdentifier]
                stringByAppendingString:@"\""];
    }
    return value;
}

@end


