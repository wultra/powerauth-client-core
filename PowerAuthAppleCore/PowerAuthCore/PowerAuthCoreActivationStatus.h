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
 The PowerAuthCoreActivationState enum defines all possible states of activation.
 The state is a part of information received together with the rest
 of the PowerAuthCoreActivationStatus object.
 */
typedef NS_ENUM(NSInteger, PowerAuthCoreActivationState) {
	/**
	 The activation is just created.
	 */
	PowerAuthCoreActivationState_Created  = 1,
	/**
	 The activation is not completed yet on the server.
	 */
	PowerAuthCoreActivationState_PendingCommit = 2,
	/**
	 The shared secure context is valid and active.
	 */
	PowerAuthCoreActivationState_Active   = 3,
	/**
	 The activation is blocked.
	 */
	PowerAuthCoreActivationState_Blocked  = 4,
	/**
	 The activation doesn't exist anymore.
	 */
	PowerAuthCoreActivationState_Removed  = 5,
	/**
	 The activation is technically blocked. You cannot use it anymore
	 for the signature calculations.
	 */
	PowerAuthCoreActivationState_Deadlock	= 128,
	
} NS_SWIFT_NAME(ActivationState);


/**
 The `ActivationStatus` object represents complete status of the activation.
 The status is typically received as an encrypted blob and you can use Session
 to decode that blob into this object.
 */
NS_SWIFT_NAME(ActivationStatus)
@interface PowerAuthCoreActivationStatus : NSObject

/**
 Not available.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/**
 State of the activation
 */
@property (nonatomic, assign, readonly) PowerAuthCoreActivationState state;
/**
 Number of failed authentication attempts in a row.
 */
@property (nonatomic, assign, readonly) UInt32 failCount;
/**
 Maximum number of allowed failed authentication attempts in a row.
 */
@property (nonatomic, assign, readonly) UInt32 maxFailCount;
/**
 Contains (maxFailCount - failCount) if state is `PowerAuthCoreActivationState_Active`,
 otherwise 0.
 */
@property (nonatomic, assign, readonly) UInt32 remainingAttempts;

// SDK-private (application should not use such interface)

/**
 Contains current version of activation
 */
@property (nonatomic, assign, readonly) UInt8 currentActivationVersion;
/**
 Contains version of activation available for upgrade.
 */
@property (nonatomic, assign, readonly) UInt8 upgradeActivationVersion;
/**
 Contains YES if upgrade to a newer protocol version is available.
 */
@property (nonatomic, assign, readonly) BOOL isProtocolUpgradeAvailable;
/**
 Returns true if dummy signature calculation is recommended to prevent
 the counter's de-synchronization.
 */
@property (nonatomic, assign, readonly) BOOL isSignatureCalculationRecommended;
/**
 Returns true if session's state should be serialized after the successful
 activation status decryption.
 */
@property (nonatomic, assign, readonly) BOOL needsSerializeSessionState;

@end

/**
 The `EncryptedActivationStatus` object contains encrypted status data and parameters
 required for the status data decryption.
 */
NS_SWIFT_NAME(EncryptedActivationStatus)
@interface PowerAuthCoreEncryptedActivationStatus : NSObject

/**
 Not available.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/// Initialize object with given parameters.
///
/// @param challenge The challenge value sent to the server. 16 bytes encoded to Base64 is expected.
/// @param statusBlob encrypted status data. The Base64 encoded string is expected.
/// @param nonce nonce returned from the server. 16 bytes encoded to Base64 is expected.
- (nonnull instancetype) initWithChallenge:(nullable NSString *)challenge
								statusBlob:(nullable NSString *)statusBlob
									 nonce:(nullable NSString *)nonce;

/**
 The challenge value sent to the server. 16 bytes encoded to Base64 is expected.
 */
@property (nonatomic, strong, nullable, readonly) NSString * challenge;
/**
 Contains encrypted status data. The Base64 encoded string is expected.
 */
@property (nonatomic, strong, nullable, readonly) NSString * encryptedStatusBlob;
/**
 Contains nonce returned from the server. 16 bytes encoded to Base64 is expected.
 */
@property (nonatomic, strong, nullable, readonly) NSString * nonce;

@end
