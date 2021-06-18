//
// Copyright 2021 Wultra s.r.o.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.
//

import Foundation

extension MiniPAS {
	
	/// Get encrypted vault key from activation entry
	/// - Parameter activationEntry: Activation entry
	/// - Throws: In case of failure
	/// - Returns: Encrypted vault key in Base64 format
	func getEncryptedVaultKey(activationEntry: ActivationEntry) throws -> String {
		guard activationEntry.state == .active else {
			throw PASErrors.invalidActivationState
		}
		let transportKey = activationEntry.keys.transportKey
		let vaultKey = activationEntry.keys.vaultKey
		let encryptedVaultKey = try MiniPASCrypto.AES_CBC_PKCS7_Encrypt(data: vaultKey, key: transportKey, ivData: MiniPASCrypto.ZERO_IV)
		return encryptedVaultKey.base64EncodedString()
	}
}
