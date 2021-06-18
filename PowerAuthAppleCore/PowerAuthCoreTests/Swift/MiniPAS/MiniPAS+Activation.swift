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
	
	/// Keys derived from shared secret
	struct ActivationKeys {
		let transportKey: Data
		let transportCtrKey: Data
		let transportIvKey: Data
		let vaultKey: Data
		let possessionKey: Data
		let knowledgeKey: Data
		let biometryKey: Data
	}
	
	/// All information about activation.
	struct ActivationEntry {
		
		/// Activation state
		enum State {
			case created
			case pendingCommit
			case active
			case blocked
			case removed
		}
		
		/// Activation version
		enum Version {
			case v2
			case v3
		}
		
		let activationId: String
		
		let activationCode: String
		let activationCodeSignature: String
		
		let serverKeyPair: ECKeyPair
		
		var devicePublicKey: Data!
		var sharedSecret: SharedSecret!
		var keys: ActivationKeys!
		var activationFingerprint: String!
		
		var ctr: Int
		var ctrData: Data
		var state: State
		var version: Version
		
		var failCount: UInt8
		var maxFailCount: UInt8
		
		var recoveryCode: String?
		var recoveryPuk: String?
	}
	
	/// Create a new activation.
	func prepareActivation(maxFailCount: UInt8 = 5) throws -> ActivationEntry {
		let uuid = UUID().uuidString
		let kp = ECKeyPair()
		let ctr = try CryptoUtils.randomBytes(count: 16)
		let code = generateActivationCode()
		let codeSignature = try masterServerKeyPair.signing().sign(data: code.data(using: .ascii)!).base64EncodedString()
		return ActivationEntry(
			activationId: uuid,
			activationCode: code,
			activationCodeSignature: codeSignature,
			serverKeyPair: kp,
			devicePublicKey: nil,
			sharedSecret: nil,
			keys: nil,
			activationFingerprint: nil,
			ctr: 0,
			ctrData: ctr,
			state: .created,
			version: .v3,
			failCount: 0,
			maxFailCount: maxFailCount,
			recoveryCode: nil,
			recoveryPuk: nil
		)
	}
	
	/// Parameters to `activate(request:)` function.
	struct ActivationRequest {
		let devicePublicKey: String
		let nextState: ActivationEntry.State
	}
	
	/// Result from `activate(request:)` function.
	struct ActivationResponse {
		let activationId: String
		let serverPublicKey: String
		let ctrData: String
		let recoveryCode: String?
		let recoveryPuk: String?
	}
	
	
	/// Activate activation object.
	/// - Parameters:
	///   - request: Request data
	///   - entry: Activation entry data
	///   - nextState: State after activate
	/// - Throws: In case of failure
	/// - Returns: Response data
	func activate(request: ActivationRequest, entry: inout ActivationEntry, nextState: ActivationEntry.State = .active) throws -> ActivationResponse {
	
		guard let devicePublicKey = Data(base64Encoded: request.devicePublicKey) else {
			throw PASErrors.invalidPublicKey
		}
		
		let recoveryCode = config.enableRecovery ? generateActivationCode() : nil
		let recoveryPuk = config.enableRecovery ? generateRecoveryPuk() : nil

		entry.devicePublicKey = devicePublicKey
		entry.sharedSecret = try entry.serverKeyPair.keyAgreement().sharedSecret(with: devicePublicKey)
		entry.keys = try entry.sharedSecret.deriveActivationKeys()
		entry.activationFingerprint = try MiniPASCrypto.CalculateActivationFingerprint(
			serverPublicKey: try entry.serverKeyPair.keyAgreement().publicKey,
			clientPublicKey: try ECKeyPair.KeyAgreement.importKey(publicKeyData: devicePublicKey),
			activationId: entry.activationId)
		entry.state = nextState
		entry.recoveryCode = recoveryCode
		entry.recoveryPuk = recoveryPuk
		
		return ActivationResponse(
			activationId: entry.activationId,
			serverPublicKey: entry.serverKeyPair.publicKey.base64EncodedString(),
			ctrData: entry.ctrData.base64EncodedString(),
			recoveryCode: recoveryCode,
			recoveryPuk: recoveryPuk
		)
	}
	
	
	/// BLock activation.
	/// - Parameter entry: Activation entry
	func blockActivation(entry: inout ActivationEntry) throws {
		if entry.state == .removed {
			throw PASErrors.invalidActivationState
		}
		entry.state = .blocked
	}
	
	
	/// Unblock activation
	/// - Parameter entry: Activation entry
	func unblockActivation(entry: inout ActivationEntry) throws {
		if entry.state != .blocked {
			throw PASErrors.invalidActivationState
		}
		entry.state = .active
		entry.failCount = 0
	}
	
	
	/// Remove activation
	/// - Parameter entry: Activation entry
	func removeActivation(entry: inout ActivationEntry) throws {
		entry.state = .removed
	}
	
	
	/// Get encrypted activation status blob.
	/// - Parameters:
	///   - challenge: Challenge from client.
	///   - entry: Activation entry
	/// - Throws: In case of failure.
	/// - Returns: Encrypted status data and nonce.
	func getEncryptedStatus(challenge: String, entry: inout ActivationEntry) throws -> (statusData: String, nonce: String) {
		
		guard let challengeData = Data(base64Encoded: challenge) else {
			throw PASErrors.invalidBase64Data
		}
		guard let nonceData = try? CryptoUtils.randomBytes(count: 16) else {
			throw PASErrors.invalidRandomGenerator
		}
		let ivData = challengeData + nonceData
		let iv = try MiniPASCrypto.KDF_Internal(key: entry.keys.transportIvKey, index: ivData)
		
		let ctrDataHash = try MiniPASCrypto.KDF_Internal(key: entry.keys.transportCtrKey, index: entry.ctrData)
		
		var blob = Data()
		blob.reserveCapacity(32)
		
		blob.append(UInt8(0xDE))				// 4 magic bytes
		blob.append(UInt8(0xC0))
		blob.append(UInt8(0xDE))
		blob.append(UInt8(0xD1))
		blob.append(entry.state.byteValue)		// current state
		blob.append(entry.version.byteValue)	// current ver
		blob.append(entry.version.byteValue)	// possible upgrade ver
		blob.append(Data(count: 5))				// 5 reserved bytes
		blob.append(UInt8(entry.ctr & 0xFF))	// CTR_BYTE = (byte)(CTR & 0xFF)
		blob.append(entry.failCount)			// fail counter
		blob.append(entry.maxFailCount)			// max fail counter
		blob.append(config.ctrLookAhead)		// ctr look ahead
		blob.append(ctrDataHash)
		
		guard blob.count == 32 else {
			fatalError("Invalid blob size")
		}

		let encryptedBlob = try MiniPASCrypto.AES_CBC_Encrypt(data: blob, key: entry.keys.transportKey, ivData: iv)
		
		return (encryptedBlob.base64EncodedString(), nonceData.base64EncodedString())
	}
	
	/// Generate activation or recovery code.
	private func generateActivationCode() -> String {
		let codes = [
			"AAAAA-AAAAA-AAAAA-AAAAA",
			"LLLLL-LLLLL-LLLLL-LQJTA",
			"KKKKK-KKKKK-KKKKK-KDJNQ",
			"MMMMM-MMMMM-MMMMM-MUTOA",
			"VVVVV-VVVVV-VVVVV-VTFVA",
			"55555-55555-55555-55YMA",
			"W65WE-3T7VI-7FBS2-A4OYA",
			"DD7P5-SY4RW-XHSNB-GO52A",
			"X3TS3-TI35Z-JZDNT-TRPFA",
			"HCPJX-U4QC4-7UISL-NJYMA",
			"XHGSM-KYQDT-URE34-UZGWQ",
			"45AWJ-BVACS-SBWHS-ABANA"
		]
		return codes.randomElement()!
	}
	
	/// Generate recovery PUK.
	private func generateRecoveryPuk() -> String {
		let low  = arc4random_uniform(100000)
		let high = arc4random_uniform(100000)
		return String(format: "%05d%05d", high, low)
	}
}

fileprivate extension SharedSecret {
	
	/// Derive all keys from shared secret.
	func deriveActivationKeys() throws -> MiniPAS.ActivationKeys {
		let sk = try MiniPASCrypto.CONVERT_32Bto16B(key: self.dataBytes)
		let transportKey = try MiniPASCrypto.KDF(key: sk, index: 1000)
		return MiniPAS.ActivationKeys(
			transportKey: transportKey,
			transportCtrKey: try MiniPASCrypto.KDF(key: transportKey, index: 4000),
			transportIvKey: try MiniPASCrypto.KDF(key: transportKey, index: 3000),
			vaultKey: try MiniPASCrypto.KDF(key: sk, index: 2000),
			possessionKey: try MiniPASCrypto.KDF(key: sk, index: 1),
			knowledgeKey: try MiniPASCrypto.KDF(key: sk, index: 2),
			biometryKey: try MiniPASCrypto.KDF(key: sk, index: 3))
	}
}

fileprivate extension MiniPAS.ActivationEntry.State {
	var byteValue: UInt8 {
		switch self {
			case .created: return 1
			case .pendingCommit: return 2
			case .active: return 3
			case .blocked: return 4
			case .removed: return 5
		}
	}
}

fileprivate extension MiniPAS.ActivationEntry.Version {
	var byteValue: UInt8 {
		switch self {
			case .v2: return 2
			case .v3: return 3
		}
	}
}

	
extension MiniPAS.ActivationResponse {
	
	/// Convert response to object required by `Session` class.
	func toClientParam() -> ValidateActivationResponseParam {
		let recovery = (recoveryCode != nil && recoveryPuk != nil) ? RecoveryData(recoveryCode: recoveryCode!, puk: recoveryPuk!) : nil
		return ValidateActivationResponseParam(
			activationId: activationId,
			serverPublicKey: serverPublicKey,
			ctrData: ctrData,
			activationRecovery: recovery
		)
	}
}
