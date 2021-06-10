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

#import <Foundation/Foundation.h>

//! Project version number for PowerAuthCore.
FOUNDATION_EXPORT double PowerAuthCoreVersionNumber;

//! Project version string for PowerAuthCore.
FOUNDATION_EXPORT const unsigned char PowerAuthCoreVersionString[];

#import <PowerAuthCore/PowerAuthCoreMacros.h>
#import <PowerAuthCore/PowerAuthCoreTypes.h>
#import <PowerAuthCore/PowerAuthCoreActivationCode.h>
#import <PowerAuthCore/PowerAuthCoreActivationCodeUtil.h>
#import <PowerAuthCore/PowerAuthCoreActivationStatus.h>
#import <PowerAuthCore/PowerAuthCoreCryptoUtils.h>
#import <PowerAuthCore/PowerAuthCoreDeprecated.h>
#import <PowerAuthCore/PowerAuthCoreEciesEncryptor.h>
#import <PowerAuthCore/PowerAuthCoreErrors.h>
#import <PowerAuthCore/PowerAuthCoreHTTPRequestData.h>
#import <PowerAuthCore/PowerAuthCoreHTTPRequestDataSignature.h>
#import <PowerAuthCore/PowerAuthCoreInfo.h>
#import <PowerAuthCore/PowerAuthCoreLog.h>
#import <PowerAuthCore/PowerAuthCorePassword.h>
#import <PowerAuthCore/PowerAuthCoreProtocolUpgradeData.h>
#import <PowerAuthCore/PowerAuthCoreRecoveryData.h>
#import <PowerAuthCore/PowerAuthCoreSessionSetup.h>
#import <PowerAuthCore/PowerAuthCoreSignatureFactorKeys.h>
#import <PowerAuthCore/PowerAuthCoreSignedData.h>
#import <PowerAuthCore/PowerAuthCoreStartActivation.h>
#import <PowerAuthCore/PowerAuthCoreValidateActivationResponse.h>
#import <PowerAuthCore/PowerAuthCoreSession.h>
