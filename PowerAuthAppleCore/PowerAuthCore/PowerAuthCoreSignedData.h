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

#import <PowerAuthCore/PowerAuthCoreMacros.h>

/**
 The `SigningDataKey` enumeration defines key type used for signature calculation.
 */
typedef NS_ENUM(NSInteger, PowerAuthCoreSigningDataKey) {
	/**
	 `KEY_SERVER_MASTER_PRIVATE` key was used for signature calculation
	 */
	PowerAuthCoreSigningDataKey_ECDSA_MasterServerKey = 0,
	/**
	 `KEY_SERVER_PRIVATE` key was used for signature calculation
	 */
	PowerAuthCoreSigningDataKey_ECDSA_PersonalizedKey = 1
	
} NS_SWIFT_NAME(SigningDataKey);


/**
 The `SignedData` object contains data and signature calculated from data.
 */
NS_SWIFT_NAME(SignedData)
@interface PowerAuthCoreSignedData : NSObject

@property (nonatomic, assign) PowerAuthCoreSigningDataKey signingDataKey;
/**
 A data protected with signature
 */
@property (nonatomic, strong, nonnull) NSData * data;
/**
 A signagure calculated for data
 */
@property (nonatomic, strong, nonnull) NSData * signature;
/**
 A data protected with signature in Base64 format. The value is
 mapped to the `data` property.
 */
@property (nonatomic, strong, nonnull) NSString * dataBase64;
/**
 A signagure calculated for data in Base64 format. The value is
 mapped to the `signature` property.
 */
@property (nonatomic, strong, nonnull) NSString * signatureBase64;

@end
