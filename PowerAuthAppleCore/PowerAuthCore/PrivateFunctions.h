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

/**
 Function creates a new `NSError` instance with `PowerAuthCoreErrorDomain` and provided error code. If message parameter
 is nil, then the default message is provided to error's localized description. If errorCode is `PowerAuthCoreErrorCode_NA`
 then function returns nil.
 */
POWERAUTH_EXTERN_C NSError * _Nullable PowerAuthCoreMakeError(PowerAuthCoreErrorCode errorCode, NSString * _Nullable message);

#ifdef __cplusplus
    #include <PowerAuth/PublicTypes.h>
    /**
     Function creates a new `NSError` instance with `PowerAuthCoreErrorDomain` and provided error code. If message parameter
     is nil, then the default message is provided to error's localized description. If errorCode is EC_Ok then function
     returns nil.
     */
    inline NSError * _Nullable PowerAuthCoreMakeError(com::wultra::powerAuth::ErrorCode errorCode, NSString * _Nullable message)
    {
        return PowerAuthCoreMakeError(static_cast<PowerAuthCoreErrorCode>(errorCode), message);
    }
#endif
