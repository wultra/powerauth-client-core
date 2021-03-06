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

#import "PowerAuthCoreHTTPRequestData.h"
#import "PrivateInterfaces.h"

using namespace com::wultra::powerAuth;

@implementation PowerAuthCoreHTTPRequestData

- (nonnull instancetype) initWithMethod:(nonnull NSString*)method
                                    uri:(nonnull NSString*)uri
{
    self = [super init];
    if (self) {
        _method = method;
        _uri = uri;
    }
    return self;
}

@end

@implementation PowerAuthCoreHTTPRequestData (Private)

- (HTTPRequestData) requestData
{
    HTTPRequestData rd;
    rd.method       = cc7::objc::CopyFromNSString(_method);
    rd.uri          = cc7::objc::CopyFromNSString(_uri);
    rd.body         = cc7::objc::CopyFromNSData(_body);
    rd.offlineNonce = cc7::objc::CopyFromNSString(_offlineNonce);
    return rd;
}

@end
