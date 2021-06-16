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
import CryptoKit

extension MiniPAS {
	
	
	/// Sign data with master server private key.
	/// - Parameter data: Data to sign.
	/// - Throws: In case of failure
	/// - Returns: ECDSA Signature
	func signDataWithMasterServerKey(data: Data) throws -> Data {
		return try masterServerKeyPair.signing().sign(data: data)
	}
	
	/// Sign data with server private key associated with activation.
	/// - Parameters:
	///   - data: Data to sign
	///   - activationEntry: Activation entry
	/// - Throws: In case of failure
	/// - Returns: ECDSA signature
	func signDataWithServerKey(data: Data, activationEntry: inout ActivationEntry) throws -> Data {
		return try activationEntry.serverKeyPair.signing().sign(data: data)
	}
	
	
	/// Data for online signature verification
	struct OnlineSignature {
		// Input data
		let method: String
		let uriId: String
		let body: Data
	
		// Signature
		let signature: String
		let version: String
		let factor: String
		let nonce: String
		let activationId: String
		let applicationKey: String
	}
	
	/// Result from signature verification
	enum SignatureResult {
		case ok
		case wrongSignature
		case invalidActivationId
		case invalidApplicationKey
		case invalidFactor
		case blocked
	}
	
	
	/// Function verifies online signature
	/// - Parameters:
	///   - onlineSignature: Online signature data
	///   - entry: Activation entry
	/// - Throws: In case of failure
	/// - Returns: Result from verification
	func verify(onlineSignature: OnlineSignature, activationEntry entry: inout ActivationEntry) throws -> SignatureResult {
		// Input validations
		guard onlineSignature.activationId == entry.activationId else {
			return .invalidActivationId
		}
		guard onlineSignature.applicationKey == applicationKey else {
			return .invalidApplicationKey
		}
		guard let signatureKeys = entry.keys.signatureKeys(for: onlineSignature.factor) else {
			return .invalidFactor
		}
		// Normalize data
		let normalizedData = onlineSignature.normalizedData(with: applicationSecret)
		
		// Try a whole look ahead window to test the signature
		var currentCtrData = entry.ctrData
		for lookAheadIndex in 0...config.ctrLookAhead {
			let currentCtr = entry.ctr + Int(lookAheadIndex)
			let nextCtrData = try MiniPASCrypto.NextCtrData(ctrData: currentCtrData)
			let signature = try calculateOnlineSignature(for: normalizedData, keys: signatureKeys, ctrData: currentCtrData)
			if signature == onlineSignature.signature {
				// match, keep the current counter and hash based counter in entry and reset counters
				entry.ctrData = nextCtrData
				entry.ctr = currentCtr
				// reset failed attempts counter when factor is higher than possession
				if signatureKeys.count > 1 {
					entry.failCount = 0
				}
				return .ok
			}
			// Move to the next iteration
			currentCtrData = nextCtrData
		}
		// Increase failed attempts counter and block the activation if max count is reached
		entry.failCount = entry.failCount + 1
		if entry.failCount == entry.maxFailCount {
			entry.state = .blocked
			return .blocked
		}
		return .wrongSignature
	}
	
	
	
	/// Calculate online signature
	/// - Parameters:
	///   - data: Data to sign
	///   - keys: Array of signature keys
	///   - ctrData: Hash based counter
	/// - Throws: In case of failure
	/// - Returns: Signature for online purposes
	private func calculateOnlineSignature(for data: Data, keys: [Data], ctrData: Data) throws -> String {
		let components = try calculateSignature(for: data, keys: keys, ctrData: ctrData)
		return Data(components.joined()).base64EncodedString()
	}
	
	
	/// Calculate offline signature
	/// - Parameters:
	///   - data: Data to sign
	///   - keys: Array of signature keys
	///   - ctrData: Hash based counter
	/// - Throws: In case of failure
	/// - Returns: Offline, decimalized signature
	private func calculateOfflineSignature(for data: Data, keys: [Data], ctrData: Data) throws -> String {
		return try calculateSignature(for: data, keys: keys, ctrData: ctrData)
			.map { try MiniPASCrypto.CalculateDecimalizedSignature(data: $0) }
			.joined(separator: "-")
	}
	
	
	/// Calculate signature components from given signature keys.
	/// - Parameters:
	///   - data: Data to sign
	///   - keys: Array of signature keys
	///   - ctrData: Hash based counter
	/// - Throws: In case of failure
	/// - Returns: Array of signature components calculated for each signature key.
	private func calculateSignature(for data: Data, keys: [Data], ctrData: Data) throws -> [Data] {
		var components = [Data]()
		for i in 0..<keys.count {
			let keySignature = keys[i]
			var keyDerived = MiniPASCrypto.HMAC_SHA256(key: keySignature, data: ctrData)
			for j in 0..<i {
				let keySignature = keys[j + 1]
				let keyDerivedCurrent = MiniPASCrypto.HMAC_SHA256(key: keySignature, data: ctrData)
				keyDerived = MiniPASCrypto.HMAC_SHA256(key: keyDerivedCurrent, data: keyDerived)
			}
			let signatureComponent = MiniPASCrypto.HMAC_SHA256(key: keyDerived, data: data)
			components.append(signatureComponent.suffix(from: 16))
		}
		return components
	}
}

fileprivate extension MiniPAS.ActivationKeys {
	
	/// Convert signature factor string to array of keys required for signature calculation.
	/// - Parameter factor: String with signature factors
	/// - Returns: Array of signature keys
	func signatureKeys(for factor: String) -> [Data]? {
		switch factor {
		case "possession":
			return [possessionKey]
		case "possession_knowledge":
			return [possessionKey, knowledgeKey]
		case "possession_biometry":
			return [possessionKey, biometryKey]
		case "possession_knowledge_biometry":
			return [possessionKey, knowledgeKey, biometryKey]
		default:
			return nil
		}
	}
}

extension MiniPAS.OnlineSignature {
	
	/// Normalize online signature's data
	/// - Parameter applicationSecret: Application secret
	/// - Returns: Normalized data for online signature calculation
	func normalizedData(with applicationSecret: String) -> Data {
		let uriIdB64 = uriId.data(using: .utf8)!.base64EncodedString()
		let bodyB64 = body.base64EncodedString()
		return "\(method)&\(uriIdB64)&\(nonce)&\(bodyB64)&\(applicationSecret)".data(using: .ascii)!
	}
}
