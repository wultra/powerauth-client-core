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
#import <PowerAuthCore/PowerAuthCoreProtocolUpgradeData.h>
#import <PowerAuthCore/PowerAuthCorePassword.h>
#import <PowerAuthCore/PowerAuthCoreEciesEncryptor.h>
#import <PowerAuthCore/PowerAuthCoreLog.h>

#include <PowerAuth/PublicTypes.h>
#include <PowerAuth/Password.h>
#include <PowerAuth/ECIES.h>

#include <cc7/objc/ObjcHelper.h>

/*
 This header contains various private interfaces, internally used
 in the PowerAuthCore's Objective-C wrappper. This header contains C++ types,
 so it's not available for Objective-C or Swift codes.
 */

@interface PowerAuthCorePassword (Private)
- (com::wultra::powerAuth::Password &) passObjRef;
@end

@interface PowerAuthCoreHTTPRequestDataSignature (Private)
- (com::wultra::powerAuth::HTTPRequestDataSignature&) signatureStructRef;
@end

@interface PowerAuthCoreSignedData (Private)
- (com::wultra::powerAuth::SignedData&) signedDataRef;
@end

@interface PowerAuthCoreEciesCryptogram (Private)
- (com::wultra::powerAuth::ECIESCryptogram &) cryptogramRef;
@end

@interface PowerAuthCoreEciesEncryptor (Private)
- (id) initWithObject:(const com::wultra::powerAuth::ECIESEncryptor &)objectRef;
- (com::wultra::powerAuth::ECIESEncryptor &) encryptorRef;
@end

@protocol PowerAuthCoreProtocolUpgradeDataPrivate <PowerAuthCoreProtocolUpgradeData>
- (void) setupStructure:(com::wultra::powerAuth::ProtocolUpgradeData &)ref;
@end

/**
 Converts PowerAuthCoreSessionSetup object into SessionSetup C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreSessionSetupToStruct(PowerAuthCoreSessionSetup * setup, com::wultra::powerAuth::SessionSetup & cpp_setup);
/**
 Returns new instance of PowerAuthCoreSessionSetup object, with content copied from SessionSetup C++ structure.
 */
CC7_EXTERN_C PowerAuthCoreSessionSetup * PowerAuthCoreSessionSetupToObject(const com::wultra::powerAuth::SessionSetup & cpp_setup);

/**
 Converts PowerAuthCoreSignatureUnlockKeys object into SignatureUnlockKeys C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreSignatureUnlockKeysToStruct(PowerAuthCoreSignatureUnlockKeys * keys, com::wultra::powerAuth::SignatureUnlockKeys & cpp_keys);
/**
Converts PowerAuthCoreEncryptedActivationStatus object into EncryptedActivationStatus C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreEncryptedActivationStatusToStruct(PowerAuthCoreEncryptedActivationStatus * status, com::wultra::powerAuth::EncryptedActivationStatus& cpp_status);
/**
 Returns new instance of PowerAuthCoreActivationStatus object, with content copied from ActivationStatus C++ structure.
 */
CC7_EXTERN_C PowerAuthCoreActivationStatus * PowerAuthCoreActivationStatusToObject(const com::wultra::powerAuth::ActivationStatus& cpp_status);

/**
 Converts PowerAuthCoreHTTPRequestData object into HTTPRequestData C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreHTTPRequestDataToStruct(PowerAuthCoreHTTPRequestData * req, com::wultra::powerAuth::HTTPRequestData & cpp_req);

/**
 Converts PowerAuthCoreActivationStep1Param object into ActivationStep1Param C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreStartActivationParamToStruct(PowerAuthCoreStartActivationParam * p1, com::wultra::powerAuth::ActivationStep1Param & cpp_p1);
/**
 Returns new instance of PowerAuthCoreActivationStep1Result object, with content copied from ActivationStep1Result C++ structure.
 */
CC7_EXTERN_C PowerAuthCoreStartActivationResult * PowerAuthCoreActivationStartResultToObject(const com::wultra::powerAuth::ActivationStep1Result& cpp_r1);

/**
 Converts PowerAuthCoreActivationStep2Param object into ActivationStep2Param C++ structure.
 */
CC7_EXTERN_C void PowerAuthCoreValidateActivationResponseParamToStruct(PowerAuthCoreValidateActivationResponseParam * p2, com::wultra::powerAuth::ActivationStep2Param & cpp_p2);
/**
 Returns new instance of PowerAuthCoreActivationStep2Result object, with content copied from ActivationStep2Result C++ structure.
 */
CC7_EXTERN_C PowerAuthCoreValidateActivationResponseResult * PowerAuthCoreValidateActivationResponseResultToObject(const com::wultra::powerAuth::ActivationStep2Result& cpp_r2);

/**
 Converts PowerAuthCoreRecoveryData object into RecoveryData C++ structure
 */
CC7_EXTERN_C void PowerAuthCoreRecoveryDataToStruct(PowerAuthCoreRecoveryData * rd, com::wultra::powerAuth::RecoveryData& cpp_rd);
/**
 Returns new instance of PowerAuthCoreRecoveryData object, with content copied from RecoveryData C++ structure
 */
CC7_EXTERN_C PowerAuthCoreRecoveryData * PowerAuthCoreRecoveryDataToObject(const com::wultra::powerAuth::RecoveryData& cpp_rd);
