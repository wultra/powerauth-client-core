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

#import <PowerAuthCore/PowerAuthCoreTypes.h>
#import "PowerAuthCorePrivateImpl.h"

using namespace com::wultra::powerAuth;

#pragma mark - Public types implementation

@implementation PowerAuthCoreSessionSetup
@end

@implementation PowerAuthCoreHTTPRequestData
@end

@implementation PowerAuthCoreHTTPRequestDataSignature
{
	com::wultra::powerAuth::HTTPRequestDataSignature _signature;
}

- (com::wultra::powerAuth::HTTPRequestDataSignature&) signatureStructRef
{
	return _signature;
}

- (NSString*) version
{
	return cc7::objc::CopyToNSString(_signature.version);
}

- (NSString*) activationId
{
	return cc7::objc::CopyToNSString(_signature.activationId);
}

- (NSString*) applicationKey
{
	return cc7::objc::CopyToNSString(_signature.applicationKey);
}

- (NSString*) nonce
{
	return cc7::objc::CopyToNSString(_signature.nonce);
}

- (NSString*) factor
{
	return cc7::objc::CopyToNSString(_signature.factor);
}

- (NSString*) signature
{
	return cc7::objc::CopyToNSString(_signature.signature);
}

- (NSString*) authHeaderValue
{
	return cc7::objc::CopyToNSString(_signature.buildAuthHeaderValue());
}

@end

@implementation PowerAuthCoreSignedData
{
	com::wultra::powerAuth::SignedData _signedData;
}

- (com::wultra::powerAuth::SignedData&) signedDataRef
{
	return _signedData;
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

#ifdef DEBUG
- (NSString*) description
{
	return [NSString stringWithFormat:@"<PowerAuthCoreSignedData data=%@, signature=%@>", self.dataBase64, self.signatureBase64];
}
#endif

@end

@implementation PowerAuthCoreSignatureUnlockKeys
@end

@implementation PowerAuthCoreRecoveryData
@end

@implementation PowerAuthCoreActivationStep1Param
@end

@implementation PowerAuthCoreActivationStep1Result
@end

@implementation PowerAuthCoreActivationStep2Param
@end

@implementation PowerAuthCoreActivationStep2Result
@end

@implementation PowerAuthCoreEncryptedActivationStatus
@end

@implementation PowerAuthCoreActivationStatus
{
	com::wultra::powerAuth::ActivationStatus _status;
}

- (id) initWithStatusStruct:(const com::wultra::powerAuth::ActivationStatus&)statusStruct
{
	self = [super init];
	if (self) {
		_status = statusStruct;
	}
	return self;
}

- (PowerAuthCoreActivationState) state
{
	return static_cast<PowerAuthCoreActivationState>(_status.state);
}

- (UInt32) failCount
{
	return _status.failCount;
}

- (UInt32) maxFailCount
{
	return _status.maxFailCount;
}

- (UInt32) remainingAttempts
{
	if (_status.state == ActivationStatus::Active) {
		if (_status.maxFailCount >= _status.failCount) {
			return _status.maxFailCount - _status.failCount;
		}
	}
	return 0;
}

#ifdef DEBUG
- (NSString*) description
{
	NSString * status_str;
	switch (_status.state) {
		case ActivationStatus::Created:			status_str = @"CREATED"; break;
		case ActivationStatus::PendingCommit:	status_str = @"PENDING_COMMIT"; break;
		case ActivationStatus::Active:			status_str = @"ACTIVE"; break;
		case ActivationStatus::Blocked:			status_str = @"BLOCKED"; break;
		case ActivationStatus::Removed:			status_str = @"REMOVED"; break;
		case ActivationStatus::Deadlock:		status_str = @"DEADLOCK"; break;
		default:
			status_str = @"<<unknown>>"; break;
			
	}
	bool upgrade = _status.isProtocolUpgradeAvailable();
	return [NSString stringWithFormat:@"<PowerAuthCoreActivationStatus %@, fails %@/%@%@>", status_str, @(_status.failCount), @(_status.maxFailCount), upgrade ? @", upgrade" : @""];
}
#endif

// Private

- (UInt8) currentActivationVersion
{
	return _status.currentVersion;
}

- (UInt8) upgradeActivationVersion
{
	return _status.upgradeVersion;
}

- (BOOL) isProtocolUpgradeAvailable
{
	return _status.isProtocolUpgradeAvailable();
}

- (BOOL) isSignatureCalculationRecommended
{
	return _status.isSignatureCalculationRecommended();
}

- (BOOL) needsSerializeSessionState
{
	return _status.needsSerializeSessionState();
}

@end


#pragma mark - Conversion routines

void PowerAuthCoreSessionSetupToStruct(PowerAuthCoreSessionSetup * setup, com::wultra::powerAuth::SessionSetup & cpp_setup)
{
	cpp_setup.applicationKey		= cc7::objc::CopyFromNSString(setup.applicationKey);
	cpp_setup.applicationSecret		= cc7::objc::CopyFromNSString(setup.applicationSecret);
	cpp_setup.masterServerPublicKey	= cc7::objc::CopyFromNSString(setup.masterServerPublicKey);
	cpp_setup.externalEncryptionKey = cc7::objc::CopyFromNSData(setup.externalEncryptionKey);
	cpp_setup.sessionIdentifier		= setup.sessionIdentifier;
}

PowerAuthCoreSessionSetup * PowerAuthCoreSessionSetupToObject(const com::wultra::powerAuth::SessionSetup & cpp_setup)
{
	PowerAuthCoreSessionSetup * result = [[PowerAuthCoreSessionSetup alloc] init];
	result.applicationKey			= cc7::objc::CopyToNSString(cpp_setup.applicationKey);
	result.applicationSecret		= cc7::objc::CopyToNSString(cpp_setup.applicationSecret);
	result.masterServerPublicKey	= cc7::objc::CopyToNSString(cpp_setup.masterServerPublicKey);
	result.sessionIdentifier		= cpp_setup.sessionIdentifier;
	result.externalEncryptionKey	= cc7::objc::CopyToNullableNSData(cpp_setup.externalEncryptionKey);
	return result;
}

void PowerAuthCoreSignatureUnlockKeysToStruct(PowerAuthCoreSignatureUnlockKeys * keys, com::wultra::powerAuth::SignatureUnlockKeys & cpp_keys)
{
	cpp_keys.possessionUnlockKey	= cc7::objc::CopyFromNSData(keys.possessionUnlockKey);
	cpp_keys.biometryUnlockKey		= cc7::objc::CopyFromNSData(keys.biometryUnlockKey);
	if (keys.userPassword != nil) {
		cpp_keys.userPassword		= [keys.userPassword passObjRef].passwordData();
	} else {
		cpp_keys.userPassword.clear();
	}
}

void PowerAuthCoreHTTPRequestDataToStruct(PowerAuthCoreHTTPRequestData * req, com::wultra::powerAuth::HTTPRequestData & cpp_req)
{
	cpp_req.body					= cc7::objc::CopyFromNSData(req.body);
	cpp_req.method					= cc7::objc::CopyFromNSString(req.method);
	cpp_req.uri						= cc7::objc::CopyFromNSString(req.uri);
	cpp_req.offlineNonce			= cc7::objc::CopyFromNSString(req.offlineNonce);
}

void PowerAuthCoreEncryptedActivationStatusToStruct(PowerAuthCoreEncryptedActivationStatus * status, com::wultra::powerAuth::EncryptedActivationStatus& cpp_status)
{
	cpp_status.challenge 			= cc7::objc::CopyFromNSString(status.challenge);
	cpp_status.encryptedStatusBlob	= cc7::objc::CopyFromNSString(status.encryptedStatusBlob);
	cpp_status.nonce				= cc7::objc::CopyFromNSString(status.nonce);
}

PowerAuthCoreActivationStatus * PowerAuthCoreActivationStatusToObject(const com::wultra::powerAuth::ActivationStatus& cpp_status)
{
	return [[PowerAuthCoreActivationStatus alloc] initWithStatusStruct:cpp_status];
}

void PowerAuthCoreActivationStep1ParamToStruct(PowerAuthCoreActivationStep1Param * p1, com::wultra::powerAuth::ActivationStep1Param & cpp_p1)
{
	cpp_p1.activationCode			= cc7::objc::CopyFromNSString(p1.activationCode.activationCode);
	cpp_p1.activationSignature		= cc7::objc::CopyFromNSString(p1.activationCode.activationSignature);
}

PowerAuthCoreActivationStep1Result * PowerAuthCoreActivationStep1ResultToObject(const com::wultra::powerAuth::ActivationStep1Result& cpp_r1)
{
	PowerAuthCoreActivationStep1Result * res = [[PowerAuthCoreActivationStep1Result alloc] init];
	res.devicePublicKey				= cc7::objc::CopyToNSString(cpp_r1.devicePublicKey);
	return res;
}

void PowerAuthCoreActivationStep2ParamToStruct(PowerAuthCoreActivationStep2Param * p2, com::wultra::powerAuth::ActivationStep2Param & cpp_p2)
{
	cpp_p2.activationId				= cc7::objc::CopyFromNSString(p2.activationId);
	cpp_p2.serverPublicKey			= cc7::objc::CopyFromNSString(p2.serverPublicKey);
	cpp_p2.ctrData					= cc7::objc::CopyFromNSString(p2.ctrData);
	PowerAuthCoreRecoveryDataToStruct(p2.activationRecovery, cpp_p2.activationRecovery);
}

PowerAuthCoreActivationStep2Result * PowerAuthCoreActivationStep2ResultToObject(const com::wultra::powerAuth::ActivationStep2Result& cpp_r2)
{
	PowerAuthCoreActivationStep2Result * res = [[PowerAuthCoreActivationStep2Result alloc] init];
	res.activationFingerprint		= cc7::objc::CopyToNSString(cpp_r2.activationFingerprint);
	return res;
}

void PowerAuthCoreRecoveryDataToStruct(PowerAuthCoreRecoveryData * rd, com::wultra::powerAuth::RecoveryData& cpp_rd)
{
	cpp_rd.recoveryCode	= cc7::objc::CopyFromNSString(rd.recoveryCode);
	cpp_rd.puk			= cc7::objc::CopyFromNSString(rd.puk);
}

PowerAuthCoreRecoveryData * PowerAuthCoreRecoveryDataToObject(const com::wultra::powerAuth::RecoveryData& cpp_rd)
{
	if (cpp_rd.isEmpty()) {
		CC7_ASSERT(false, "Empty structure should be handled before the conversion.");
		return nil;
	}
	PowerAuthCoreRecoveryData * res = [[PowerAuthCoreRecoveryData alloc] init];
	res.recoveryCode	= cc7::objc::CopyToNSString(cpp_rd.recoveryCode);
	res.puk				= cc7::objc::CopyToNSString(cpp_rd.puk);
	return res;
}
