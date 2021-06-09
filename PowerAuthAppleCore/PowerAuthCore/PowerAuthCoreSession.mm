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

#import <PowerAuthCore/PowerAuthCoreSession.h>
#import <PowerAuthCore/PowerAuthCoreMacros.h>
#import "PrivateFunctions.h"

#include <PowerAuth/Session.h>
#include <PowerAuth/Debug.h>

using namespace com::wultra::powerAuth;

@implementation PowerAuthCoreSession
{
	Session _session;
}

#pragma mark - Initialization / Reset

- (instancetype) initWithSessionSetup:(PowerAuthCoreSessionSetup *)setup
{
	self = [super init];
	if (self) {
		SessionSetup cpp_setup;
		PowerAuthCoreSessionSetupToStruct(setup, cpp_setup);
		_session.setSessionSetup(cpp_setup);
	}
	return self;
}

- (void) resetSession
{
	_session.resetSession();
}

#pragma mark - Read only getters

- (PowerAuthCoreSessionSetup*) sessionSetup
{
	const SessionSetup * cpp_setup = _session.sessionSetup();
	return cpp_setup != nullptr ? PowerAuthCoreSessionSetupToObject(*cpp_setup) : nil;
}

- (UInt32) sessionIdentifier
{
	return _session.sessionIdentifier();
}

- (BOOL) hasValidSetup
{
	return _session.hasValidSetup();
}

- (BOOL) canStartActivation
{
	return _session.canStartActivation();
}

- (BOOL) hasPendingActivation
{
	return _session.hasPendingActivation();
}

- (BOOL) hasValidActivation
{
	return _session.hasValidActivation();
}

- (BOOL) hasProtocolUpgradeAvailable
{
	return _session.hasProtocolUpgradeAvailable();
}

- (BOOL) hasPendingProtocolUpgrade
{
	return _session.hasPendingProtocolUpgrade();
}

- (PowerAuthCoreProtocolVersion) protocolVersion
{
	return (PowerAuthCoreProtocolVersion) _session.protocolVersion();
}

#pragma mark - Serialization

- (NSData *) serializedState
{
	return cc7::objc::CopyToNSData(_session.saveSessionState());
}


- (BOOL) deserializeState:(NSData *)state
					error:(NSError **)error

{
	auto ec = _session.loadSessionState(cc7::ByteRange(state.bytes, state.length));
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
}



#pragma mark - Activation

- (NSString *) activationIdentifier
{
	return cc7::objc::CopyToNullableNSString(_session.activationIdentifier());
}

- (NSString *) activationFingerprint
{
	return cc7::objc::CopyToNullableNSString(_session.activationFingerprint());
}

- (PowerAuthCoreStartActivationResult*) startActivationWithParam:(PowerAuthCoreStartActivationParam*)param
														   error:(NSError **)error
{
	ActivationStep1Param cpp_p1;
	ActivationStep1Result cpp_r1;
	PowerAuthCoreStartActivationParamToStruct(param, cpp_p1);
	auto ec = _session.startActivation(cpp_p1, cpp_r1);
	if (error) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok ? PowerAuthCoreActivationStartResultToObject(cpp_r1) : nil;
}


- (PowerAuthCoreValidateActivationResponseResult*) validateActivationResponseWithParam:(PowerAuthCoreValidateActivationResponseParam*)param
																				 error:(NSError **)error
{
	ActivationStep2Param cpp_p2;
	ActivationStep2Result cpp_r2;
	PowerAuthCoreValidateActivationResponseParamToStruct(param, cpp_p2);
	auto ec = _session.validateActivationResponse(cpp_p2, cpp_r2);
	if (error) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok ? PowerAuthCoreValidateActivationResponseResultToObject(cpp_r2) : nil;
}


- (BOOL) completeActivationWithKeys:(PowerAuthCoreSignatureUnlockKeys*)keys
							  error:(NSError **)error
{
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(keys, cpp_keys);
	auto ec = _session.completeActivation(cpp_keys);
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
}



#pragma mark - Activation status

- (PowerAuthCoreActivationStatus*) decodeActivationStatus:(PowerAuthCoreEncryptedActivationStatus *)encryptedStatus
													 keys:(PowerAuthCoreSignatureUnlockKeys*)unlockKeys
													error:(NSError **)error
{
	EncryptedActivationStatus cpp_encrypted_status;
	SignatureUnlockKeys cpp_keys;
	ActivationStatus cpp_status;
	PowerAuthCoreEncryptedActivationStatusToStruct(encryptedStatus, cpp_encrypted_status);
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	auto ec = _session.decodeActivationStatus(cpp_encrypted_status, cpp_keys, cpp_status);
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok ? PowerAuthCoreActivationStatusToObject(cpp_status) : nil;
}



#pragma mark - Data signing

- (NSData*) prepareKeyValueDictionaryForDataSigning:(NSDictionary<NSString*, NSString*>*)dictionary
											  error:(NSError **)error
{
	__block std::map<std::string, std::string> map;
	__block NSError * failure = nil;
	[dictionary enumerateKeysAndObjectsUsingBlock:^(NSString * key, NSString * value, BOOL * stop) {
		if (![key isKindOfClass:[NSString class]] || ![value isKindOfClass:[NSString class]]) {
			failure = PowerAuthCoreMakeError(EC_WrongParam, @"Wrong type of object or key in provided NSDictionary.");
			*stop = YES;
			return;
		}
		map[std::string(key.UTF8String)] = std::string(value.UTF8String);
	}];
	if (failure) {
		if (error) {
			*error = failure;
		}
		return nil;
	}
	cc7::ByteArray normalized_data = Session::prepareKeyValueMapForDataSigning(map);
	return cc7::objc::CopyToNSData(normalized_data);
}


- (PowerAuthCoreHTTPRequestDataSignature*) signHttpRequestData:(PowerAuthCoreHTTPRequestData*)requestData
														  keys:(PowerAuthCoreSignatureUnlockKeys*)unlockKeys
														factor:(PowerAuthCoreSignatureFactor)factor
														 error:(NSError **)error
{
	HTTPRequestData request;
	PowerAuthCoreHTTPRequestDataToStruct(requestData, request);
	SignatureFactor cpp_factor	= static_cast<SignatureFactor>(factor);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	
	PowerAuthCoreHTTPRequestDataSignature * signature = [[PowerAuthCoreHTTPRequestDataSignature alloc] init];
	auto ec = _session.signHTTPRequestData(request, cpp_keys, cpp_factor, [signature signatureStructRef]);
	if (error) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok ? signature : nil;
}


- (NSString*) httpAuthHeaderName
{
	return cc7::objc::CopyToNSString(_session.httpAuthHeaderName());
}


- (BOOL) verifyServerSignedData:(nonnull PowerAuthCoreSignedData*)signedData
						  error:(NSError **)error
{
	ErrorCode ec;
	if (signedData != nil) {
		ec = _session.verifyServerSignedData(signedData.signedDataRef);
		// Don't throw an error for EC_WrongSignature.
		if (ec == EC_Ok || ec == EC_WrongSignature) {
			return ec == EC_Ok;
		}
	} else {
		ec = EC_WrongParam;
	}
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return NO;
}


#pragma mark - Signature keys management

- (BOOL) changeUserPassword:(PowerAuthCorePassword *)old_password
				newPassword:(PowerAuthCorePassword*)new_password
					  error:(NSError **)error
{
	ErrorCode ec;
	if (old_password != nil && new_password != nil) {
		ec = _session.changeUserPassword([old_password passObjRef].passwordData(), [new_password passObjRef].passwordData());
	} else {
		ec = EC_WrongParam;
	}
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
 }

- (BOOL) addBiometryFactor:(NSString *)cVaultKey
					  keys:(PowerAuthCoreSignatureUnlockKeys*)unlockKeys
					 error:(NSError **)error
{
	std::string cpp_c_vault_key = cc7::objc::CopyFromNSString(cVaultKey);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	auto ec = _session.addBiometryFactor(cpp_c_vault_key, cpp_keys);
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
}

- (BOOL) hasBiometryFactor
{
	return (BOOL) _session.hasBiometryFactor();
}

- (BOOL) removeBiometryFactor:(NSError **)error
{
	auto ec = _session.removeBiometryFactor();
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
}


#pragma mark - Vault operations

- (NSData*) deriveCryptographicKeyFromVaultKey:(NSString*)cVaultKey
										  keys:(PowerAuthCoreSignatureUnlockKeys*)unlockKeys
									  keyIndex:(UInt64)keyIndex
										 error:(NSError **)error
{
	std::string cpp_c_vault_key = cc7::objc::CopyFromNSString(cVaultKey);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		
	cc7::ByteArray cpp_derived_key;
	auto ec = _session.deriveCryptographicKeyFromVaultKey(cpp_c_vault_key, cpp_keys, keyIndex, cpp_derived_key);
	if (error) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok ? cc7::objc::CopyToNSData(cpp_derived_key) : nil;
}

- (NSData*) signDataWithDevicePrivateKey:(NSString*)cVaultKey
									keys:(PowerAuthCoreSignatureUnlockKeys*)unlockKeys
									data:(NSData*)data
								   error:(NSError **)error
{
	std::string cpp_c_vault_key	= cc7::objc::CopyFromNSString(cVaultKey);
	cc7::ByteArray cpp_data		= cc7::objc::CopyFromNSData(data);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
		
	cc7::ByteArray cpp_signature;
	auto ec = _session.signDataWithDevicePrivateKey(cpp_c_vault_key, cpp_keys, cpp_data, cpp_signature);
	if (error) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok ? cc7::objc::CopyToNSData(cpp_signature) : nil;
}


#pragma mark - External encryption key

- (BOOL) hasExternalEncryptionKey
{
	return _session.hasExternalEncryptionKey();
}

- (BOOL) setExternalEncryptionKey:(NSData *)externalEncryptionKey
							error:(NSError **)error
{
	auto ec = _session.setExternalEncryptionKey(cc7::objc::CopyFromNSData(externalEncryptionKey));
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
}

- (BOOL) addExternalEncryptionKey:(nonnull NSData *)externalEncryptionKey
							error:(NSError * _Nullable * _Nullable)error
{
	auto ec = _session.addExternalEncryptionKey(cc7::objc::CopyFromNSData(externalEncryptionKey));
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
}

- (BOOL) removeExternalEncryptionKey:(NSError * _Nullable * _Nullable)error;
{
	auto ec = _session.removeExternalEncryptionKey();
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
}


#pragma mark - ECIES

- (PowerAuthCoreEciesEncryptor*) eciesEncryptorForScope:(PowerAuthCoreEciesEncryptorScope)scope
												   keys:(PowerAuthCoreSignatureUnlockKeys*)unlockKeys
											sharedInfo1:(NSData*)sharedInfo1
												  error:(NSError **)error
{
	ECIESEncryptorScope cpp_scope   = (ECIESEncryptorScope)scope;
	cc7::ByteArray cpp_shared_info1 = cc7::objc::CopyFromNSData(sharedInfo1);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	
	ECIESEncryptor cpp_encryptor;
	auto ec = _session.getEciesEncryptor(cpp_scope, cpp_keys, cpp_shared_info1, cpp_encryptor);
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok ? [[PowerAuthCoreEciesEncryptor alloc] initWithObject:cpp_encryptor] : nil;
}

#pragma mark - Utilities for generic keys

+ (NSData*) normalizeSignatureUnlockKeyFromData:(NSData*)data
{
	return cc7::objc::CopyToNSData(Session::normalizeSignatureUnlockKeyFromData(cc7::ByteRange(data.bytes, data.length)));
}


+ (NSData*) generateSignatureUnlockKey
{
	return cc7::objc::CopyToNSData(Session::generateSignatureUnlockKey());
}


- (NSString*) generateActivationStatusChallenge
{
	return cc7::objc::CopyToNSString(Session::generateSignatureUnlockKey().base64String());
}


#pragma mark - Protocol upgrade

- (BOOL) startProtocolUpgrade:(NSError **)error
{
	auto ec = _session.startProtocolUpgrade();
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
}

- (PowerAuthCoreProtocolVersion) pendingProtocolUpgradeVersion
{
	return (PowerAuthCoreProtocolVersion) _session.pendingProtocolUpgradeVersion();
}

- (BOOL) applyProtocolUpgradeData:(id<PowerAuthCoreProtocolUpgradeData>)upgradeData
							error:(NSError **)error
{
	ErrorCode ec;
	if ([upgradeData conformsToProtocol:@protocol(PowerAuthCoreProtocolUpgradeDataPrivate)]) {
		id<PowerAuthCoreProtocolUpgradeDataPrivate> upgradeDataObject = (id<PowerAuthCoreProtocolUpgradeDataPrivate>)upgradeData;
		// Convert data to C++ & commit to underlying session
		ProtocolUpgradeData cpp_upgrade_data;
		[upgradeDataObject setupStructure:cpp_upgrade_data];
		ec = _session.applyProtocolUpgradeData(cpp_upgrade_data);
	} else {
		ec = EC_WrongParam;
	}
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
}

- (BOOL) finishProtocolUpgrade:(NSError **)error;
{
	auto ec = _session.finishProtocolUpgrade();
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok;
}

+ (NSString*) maxSupportedHttpProtocolVersion:(PowerAuthCoreProtocolVersion)protocolVersion
{
	return cc7::objc::CopyToNSString(Session::maxSupportedHttpProtocolVersion(static_cast<Version>(protocolVersion)));
}

#pragma mark - Recovery codes

- (BOOL) hasActivationRecoveryData
{
	return _session.hasActivationRecoveryData();
}

- (PowerAuthCoreRecoveryData*) activationRecoveryData:(NSString *)cVaultKey
												 keys:(PowerAuthCoreSignatureUnlockKeys *)unlockKeys
												error:(NSError * _Nullable * _Nullable)error
{
	std::string cpp_c_vault_key = cc7::objc::CopyFromNSString(cVaultKey);
	SignatureUnlockKeys cpp_keys;
	PowerAuthCoreSignatureUnlockKeysToStruct(unlockKeys, cpp_keys);
	
	RecoveryData cpp_recovery_data;
	auto ec = _session.getActivationRecoveryData(cpp_c_vault_key, cpp_keys, cpp_recovery_data);
	if (error != nil) {
		*error = PowerAuthCoreMakeError(ec, nil);
	}
	return ec == EC_Ok ? PowerAuthCoreRecoveryDataToObject(cpp_recovery_data) : nil;
}

@end
