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

#import "PowerAuthCoreActivationStatus.h"
#import "PrivateInterfaces.h"

using namespace com::wultra::powerAuth;

#pragma mark - Status

@implementation PowerAuthCoreActivationStatus
{
    ActivationStatus _status;
}

- (PowerAuthCoreActivationState) state
{
    return static_cast<PowerAuthCoreActivationState>(_status.state);
}

- (UInt32) failCount
{
    return _status.failCount;
}

- (UInt32) maxFailCount
{
    return _status.maxFailCount;
}

- (UInt32) remainingAttempts
{
    if (_status.state == ActivationStatus::Active) {
        if (_status.maxFailCount >= _status.failCount) {
            return _status.maxFailCount - _status.failCount;
        }
    }
    return 0;
}

- (NSString*) description
{
    NSString * status_str;
    switch (_status.state) {
        case ActivationStatus::Created:         status_str = @"CREATED"; break;
        case ActivationStatus::PendingCommit:   status_str = @"PENDING_COMMIT"; break;
        case ActivationStatus::Active:          status_str = @"ACTIVE"; break;
        case ActivationStatus::Blocked:         status_str = @"BLOCKED"; break;
        case ActivationStatus::Removed:         status_str = @"REMOVED"; break;
        case ActivationStatus::Deadlock:        status_str = @"DEADLOCK"; break;
        default:
            status_str = @"<<unknown>>"; break;
            
    }
    bool upgrade = _status.isProtocolUpgradeAvailable();
    return [NSString stringWithFormat:@"<PowerAuthCoreActivationStatus %@, fails %@/%@%@>", status_str, @(_status.failCount), @(_status.maxFailCount), upgrade ? @", upgrade" : @""];
}

// Private

- (UInt8) currentActivationVersion
{
    return _status.currentVersion;
}

- (UInt8) upgradeActivationVersion
{
    return _status.upgradeVersion;
}

- (BOOL) isProtocolUpgradeAvailable
{
    return _status.isProtocolUpgradeAvailable();
}

- (BOOL) isSignatureCalculationRecommended
{
    return _status.isSignatureCalculationRecommended();
}

- (BOOL) needsSerializeSessionState
{
    return _status.needsSerializeSessionState();
}

@end

@implementation PowerAuthCoreActivationStatus (Private)

- (instancetype) initWithStruct:(const com::wultra::powerAuth::ActivationStatus&)structRef
{
    self = [super init];
    if (self) {
        _status = structRef;
    }
    return self;
}

@end

#pragma mark - Encrypted status

@implementation PowerAuthCoreEncryptedActivationStatus

- (instancetype) initWithChallenge:(NSString *)challenge
                        statusBlob:(NSString *)statusBlob
                             nonce:(NSString *)nonce
{
    self = [super init];
    if (self) {
        _challenge = challenge;
        _encryptedStatusBlob = statusBlob;
        _nonce = nonce;
    }
    return self;
}

@end

@implementation PowerAuthCoreEncryptedActivationStatus (Private)

- (EncryptedActivationStatus) statusData
{
    EncryptedActivationStatus sd;
    sd.challenge            = cc7::objc::CopyFromNSString(_challenge);
    sd.encryptedStatusBlob  = cc7::objc::CopyFromNSString(_encryptedStatusBlob);
    sd.nonce                = cc7::objc::CopyFromNSString(_nonce);
    return sd;
}

@end
