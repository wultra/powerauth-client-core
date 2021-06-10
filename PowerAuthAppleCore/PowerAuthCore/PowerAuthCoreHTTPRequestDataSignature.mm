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

#import "PowerAuthCoreHTTPRequestDataSignature.h"
#import "PrivateInterfaces.h"

using namespace com::wultra::powerAuth;

@implementation PowerAuthCoreHTTPRequestDataSignature

- (instancetype) initWithStruct:(const HTTPRequestDataSignature &)structRef
{
	self = [super init];
	if (self) {
		_version			= cc7::objc::CopyToNSString(structRef.version);
		_activationId		= cc7::objc::CopyToNSString(structRef.activationId);
		_applicationKey		= cc7::objc::CopyToNSString(structRef.applicationKey);
		_nonce				= cc7::objc::CopyToNSString(structRef.nonce);
		_factor				= cc7::objc::CopyToNSString(structRef.factor);
		_signature			= cc7::objc::CopyToNSString(structRef.signature);
		_authHeaderValue	= cc7::objc::CopyToNSString(structRef.buildAuthHeaderValue());
	}
	return self;
}

@end
