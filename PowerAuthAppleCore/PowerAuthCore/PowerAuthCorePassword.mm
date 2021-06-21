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

#import <PowerAuthCore/PowerAuthCorePassword.h>
#import "PrivateInterfaces.h"

#pragma mark - Password -

using namespace com::wultra::powerAuth;

@implementation PowerAuthCorePassword
{
@protected
    Password _password;
}

- (instancetype) init
{
    return [self initEmptyAsMutable:NO];
}

- (instancetype) initEmptyAsMutable:(BOOL)asMutable
{
    self = [super init];
    if (self) {
        if (asMutable) {
            _password.initAsMutable();
        } else {
            _password.initAsImmutable(cc7::ByteRange());
        }
    }
    return self;
}

+ (instancetype) passwordWithString:(NSString *)string
{
    PowerAuthCorePassword * pass = [[PowerAuthCorePassword alloc] init];
    if (pass) {
        pass->_password.initAsImmutable(cc7::MakeRange(string.UTF8String));
    }
    return pass;
}

+ (instancetype) passwordWithData:(NSData *)data
{
    PowerAuthCorePassword * pass = [[PowerAuthCorePassword alloc] init];
    if (pass) {
        pass->_password.initAsImmutable(cc7::ByteRange(data.bytes, data.length));
    }
    return pass;
}

- (NSUInteger) length
{
    return _password.length();
}

- (BOOL) isEqualToPassword:(PowerAuthCorePassword *)password
{
    if (self == password) {
        return YES;
    } else if (!password) {
        return NO;
    }
    return _password.isEqualToPassword(password->_password);
}

- (BOOL) validatePasswordComplexity:(BOOL (NS_NOESCAPE ^)(const UInt8* passphrase, NSUInteger length))validationBlock
{
    BOOL result = NO;
    const cc7::byte * plaintext_bytes = _password.passwordData().data();
    if (validationBlock && plaintext_bytes) {
        result = validationBlock(plaintext_bytes, _password.passwordData().size());
    }
    return result;
}

@end


#pragma mark - Password (Private) -

@implementation PowerAuthCorePassword (Private)

- (instancetype) initWithStruct:(const cc7::ByteRange &)structRef
{
    self = [super init];
    if (self) {
        _password.initAsImmutable(structRef);
    }
    return self;
}

- (const Password &) structRef
{
    return _password;
}

@end


#pragma mark - Mutable password -

@implementation PowerAuthCoreMutablePassword

- (id) init
{
    return [super initEmptyAsMutable:YES];
}

+ (instancetype) mutablePassword
{
    return [[self alloc] initEmptyAsMutable:YES];
}

- (void) clear
{
    _password.clear();
}

- (BOOL) addCharacter:(UInt32)character
{
    return _password.addCharacter(character);
}

- (BOOL) insertCharacter:(UInt32)character atIndex:(NSUInteger)index
{
    return _password.insertCharacter(character, index);
}

- (BOOL) removeLastCharacter
{
    return _password.removeLastCharacter();
}

- (BOOL) removeCharacterAtIndex:(NSUInteger)index
{
    return _password.removeCharacter(index);
}

@end
