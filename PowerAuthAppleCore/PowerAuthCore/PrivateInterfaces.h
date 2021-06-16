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

#import <PowerAuthCore/PowerAuthCoreSessionSetup.h>
#import <PowerAuthCore/PowerAuthCoreSignatureFactorKeys.h>
#import <PowerAuthCore/PowerAuthCorePassword.h>
#import <PowerAuthCore/PowerAuthCoreStartActivation.h>
#import <PowerAuthCore/PowerAuthCoreValidateActivationResponse.h>
#import <PowerAuthCore/PowerAuthCoreActivationStatus.h>
#import <PowerAuthCore/PowerAuthCoreActivationCode.h>
#import <PowerAuthCore/PowerAuthCoreProtocolUpgradeData.h>
#import <PowerAuthCore/PowerAuthCoreHTTPRequestData.h>
#import <PowerAuthCore/PowerAuthCoreHTTPRequestDataSignature.h>
#import <PowerAuthCore/PowerAuthCoreSignedData.h>
#import <PowerAuthCore/PowerAuthCoreRecoveryData.h>
#import <PowerAuthCore/PowerAuthCoreEciesEncryptor.h>

#include <PowerAuth/PublicTypes.h>
#include <PowerAuth/Password.h>
#include <PowerAuth/ActivationCode.h>
#include <PowerAuth/ECIES.h>

#include <cc7/objc/ObjcHelper.h>

/*
 This header contains various private interfaces, internally used
 in the PowerAuthCore's Objective-C wrappper. This header contains C++ types,
 so it's not available for Objective-C or Swift codes.
 */

@interface PowerAuthCoreSessionSetup (Private)
- (instancetype) initWithStruct:(const com::wultra::powerAuth::SessionSetup &)structRef;
- (const com::wultra::powerAuth::SessionSetup &) structRef;
@end

// SIGNINNG

@interface PowerAuthCorePassword (Private)
- (instancetype) initWithStruct:(const cc7::ByteRange &)structRef;
- (const com::wultra::powerAuth::Password &) structRef;
@end

@interface PowerAuthCoreSignatureFactorKeys (Private)
- (const com::wultra::powerAuth::SignatureUnlockKeys &) structRef;
- (com::wultra::powerAuth::SignatureFactor) signatureFactor;
@end

@interface PowerAuthCoreActivationCode (Private)
- (instancetype) initWithStruct:(const com::wultra::powerAuth::ActivationCode &)structRef;
- (const com::wultra::powerAuth::ActivationCode &) structRef;
@end

@interface PowerAuthCoreHTTPRequestData (Private)
- (com::wultra::powerAuth::HTTPRequestData) requestData;
@end

@interface PowerAuthCoreHTTPRequestDataSignature (Private)
- (instancetype) initWithStruct:(const com::wultra::powerAuth::HTTPRequestDataSignature &)structRef;
@end

@interface PowerAuthCoreSignedData (Private)
- (instancetype) initWithStruct:(const com::wultra::powerAuth::SignedData &)structRef;
- (const com::wultra::powerAuth::SignedData &) structRef;
@end

// RECOVERY

@interface PowerAuthCoreRecoveryData (Private)
- (instancetype) initWithStruct:(const com::wultra::powerAuth::RecoveryData &)structRef;
- (const com::wultra::powerAuth::RecoveryData &) structRef;
@end

// ACTIVATION

@interface PowerAuthCoreActivationStatus (Private)
- (instancetype) initWithStruct:(const com::wultra::powerAuth::ActivationStatus &)structRef;
@end

@interface PowerAuthCoreEncryptedActivationStatus (Private)
- (com::wultra::powerAuth::EncryptedActivationStatus) statusData;
@end

@interface PowerAuthCoreStartActivationParam (Private)
- (com::wultra::powerAuth::ActivationStep1Param) activationData;
@end

@interface PowerAuthCoreStartActivationResult (Private)
- (instancetype) initWithStruct:(const com::wultra::powerAuth::ActivationStep1Result &)structRef;
@end

@interface PowerAuthCoreValidateActivationResponseParam (Private)
- (com::wultra::powerAuth::ActivationStep2Param) activationData;
@end

@interface PowerAuthCoreValidateActivationResponseResult (Private)
- (instancetype) initWithStruct:(const com::wultra::powerAuth::ActivationStep2Result &)structRef;
@end

// ECIES

@interface PowerAuthCoreEciesCryptogram (Private)
- (com::wultra::powerAuth::ECIESCryptogram &) cryptogramRef;
@end

@interface PowerAuthCoreEciesEncryptor (Private)
- (id) initWithObject:(const com::wultra::powerAuth::ECIESEncryptor &)objectRef;
- (com::wultra::powerAuth::ECIESEncryptor &) encryptorRef;
@end


// UPGRADE

@protocol PowerAuthCoreProtocolUpgradeDataPrivate <PowerAuthCoreProtocolUpgradeData>
- (void) setupStructure:(com::wultra::powerAuth::ProtocolUpgradeData &)ref;
@end
