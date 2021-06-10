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
 The PowerAuthCoreHTTPRequestData object contains all data required for calculating signature from
 HTTP request. You have to provide values at least non-empty strings to `method` and `uri`
 members, to pass a data validation.
 */
NS_SWIFT_NAME(HTTPRequestData)
@interface PowerAuthCoreHTTPRequestData : NSObject

/**
 Use designated initializer.
 */
- (nonnull instancetype)init NS_UNAVAILABLE;

/// Initialize object with HTTP method and URI identifier.
/// @param method HTTP method ("POST", "GET", "HEAD", "PUT", "DELETE" value is expected).
/// @param uri URI identifier of the request. This is pre-agreed constant, typically equal to a relative URI.
- (nonnull instancetype) initWithMethod:(nonnull NSString*)method
									uri:(nonnull NSString*)uri;
/**
 HTTP method ("POST", "GET", "HEAD", "PUT", "DELETE" value is expected)
 */
@property (nonatomic, strong, readonly, nonnull) NSString * method;
/**
 URI identifier of the request. This is pre-agreed constant, typically equal to a relative URI.
 */
@property (nonatomic, strong, readonly, nonnull) NSString * uri;
/**
 A whole POST body or data blob prepared in 'Session::prepareKeyValueMapForDataSigning'
 method. You can also calculate signature for an empty request with no body or without
 any GET parameters. In this case the member may be empty.
 */
@property (nonatomic, strong, nullable) NSData * body;
/**
 Optional, contains NONCE generated externally. The value should be used for offline data
 signing purposes only. The Base64 string is expected.
 */
@property (nonatomic, strong, nullable) NSString * offlineNonce;

@end
