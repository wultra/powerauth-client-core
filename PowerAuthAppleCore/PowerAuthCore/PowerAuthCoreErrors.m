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

#import <PowerAuthCore/PowerAuthCoreErrors.h>

NSString * const PowerAuthCoreErrorDomain = @"PowerAuthCoreErrorDomain";

@implementation NSError (PowerAuthCore)

- (PowerAuthCoreErrorCode) powerAuthCoreErrorCode
{
	if ([self.domain isEqualToString:PowerAuthCoreErrorDomain]) {
		return (PowerAuthCoreErrorCode)self.code;
	}
	return PowerAuthCoreErrorCode_NA;
}

@end

static NSString * _GetDefaultErrorDescription(PowerAuthCoreErrorCode ec, NSString * message)
{
	// Keep original message, if it's already provided.
	if (message) {
		return message;
	}
	switch (ec) {
		case PowerAuthCoreErrorCode_WrongSetup:
			return @"Session has invalid setup";
		case PowerAuthCoreErrorCode_WrongState:
			return @"Function called in wrong object state";
		case PowerAuthCoreErrorCode_WrongCode:
			return @"Wrong Activation or Recovery code";
		case PowerAuthCoreErrorCode_WrongData:
			return @"Invalid input data";
		case PowerAuthCoreErrorCode_WrongParam:
			return @"Invalid or empty parameter provided to the function";
		case PowerAuthCoreErrorCode_Encryption:
			return @"Data encryption or decryption failed";
		case PowerAuthCoreErrorCode_WrongSignature:
			return @"Invalid digital signature";
		default:
			return nil;
	}
}

NSError * PowerAuthCoreMakeError(PowerAuthCoreErrorCode ec, NSString * message)
{
	if (ec == PowerAuthCoreErrorCode_NA) {
		return nil;
	}
	NSDictionary * info = @{ NSLocalizedDescriptionKey: _GetDefaultErrorDescription(ec, message)};
	return [NSError errorWithDomain:PowerAuthCoreErrorDomain code:ec userInfo:info];
}
