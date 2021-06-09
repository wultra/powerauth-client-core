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
 Domain for `NSError` produced by this module.
 */
POWERAUTH_EXTERN_C NSString * __nonnull const PowerAuthCoreErrorDomain;

/**
 The PowerAuthCoreErrorCode enumeration defines all possible error codes
 produced by PowerAuthCoreSession and other objects. You normally need
 to check only if operation ended with EC_Ok or not. All other codes are
 only hints and should be used only for debugging purposes.
 
 For example, if the operation fails at PowerAuthCoreErrorCode_WrongState or PowerAuthCoreErrorCode_WrongParam,
 then it's usualy your fault and you're using the session in wrong way.
 */
typedef NS_ENUM(NSInteger, PowerAuthCoreErrorCode) {
	/**
	 PowerAuthErrorCode is not available in NSError object. This
	 constant is returned when you call `NSError.powerAuthCoreErrorCode`
	 on objed that has different than `PowerAuthCoreErrorDomain`
	 */
	PowerAuthCoreErrorCode_NA				= 0,
	/**
	 You have called Session method while session has invalid setup.
	 */
	PowerAuthCoreErrorCode_WrongSetup		= 1,
	/**
	 You have called method in wrong session's state. Usually that
	 means that you're using session in a  wrong way. This kind
	 of error should not be propagated to the UI. It's your
	 responsibility to handle session states correctly.
	 */
	PowerAuthCoreErrorCode_WrongState		= 2,
	/**
	 You have called method with wrong or missing parameters.
	 Usually this error code means that you're using method
	 in wrong way and you did not provide all required data.
	 This kind of error should not be propagated to UI. It's
	 your responsibility to handle all user's inputs
	 and validate all responses from server before you
	 ask core for processing.
	 */
	PowerAuthCoreErrorCode_WrongParam		= 3,
	/**
	 You have provided a wrong activation or recovery code.
	 You should use ActivationCodeUtil class to vlaidate user
	 inputs, before you call other PowerAuth functions.
	 */
	PowerAuthCoreErrorCode_WrongCode		= 4,
	/**
	 The provided digital signature is not valid. This error is also
	 returned when the digital signature is missing, but it's required.
	 */
	PowerAuthCoreErrorCode_WrongSignature	= 5,
	/**
	 The provided data is in wrong format. This error code is typically
	 returned when decoding of important parameter failed. For example,
	 if BASE64 encoded value is in wrong format.
	 */
	PowerAuthCoreErrorCode_WrongData		= 6,
	/**
	 The encryption or decryption failed. Whatever that means it's usually
	 very wrong and the UI response depends on what method did you call.
	 Typically, you have to perform retry or restart for the whole process.
	 */
	PowerAuthCoreErrorCode_Encryption		= 7,
	
} NS_SWIFT_NAME(ErrorCode);

@interface NSError (PowerAuthCore)
/**
 Contains `PowerAuthCoreErrorCode` enum in case this error was created by PowerAuthCore module,
 otherwise `PowerAuthCoreErrorCode_NA`.
 */
@property (nonatomic, readonly) PowerAuthCoreErrorCode powerAuthCoreErrorCode;

@end
