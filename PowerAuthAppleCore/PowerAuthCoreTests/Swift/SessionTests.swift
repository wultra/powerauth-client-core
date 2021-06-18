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

import XCTest
@testable import PowerAuthCore

class SessionTests: XCTestCase {

	var server: MiniPAS!
	var session: Session!
	var activationHelper: ActivationHelper!
	
    override func setUpWithError() throws {
    }

    override func tearDownWithError() throws {
    }

	/// Prepare `MiniPAS` instance and `Session` instance for tests.
	/// - Parameter config: Server's config
	/// - Throws: In case of failure
	func configureServerAndSession(config: MiniPAS.Config = .default) throws {
		server = try MiniPAS.craete(with: config)
		session = Session(setup: server.getSessionSetup())
		activationHelper = ActivationHelper(server: server, session: session)
	}
	
	// MARK: - Activation -
	
    func testCreateActivationWithBiometry() throws {
		try configureServerAndSession()
		try [ ActivationHelper.ActivationType.noCode, .code, .codeWithSignature ].forEach { activationType in
			try activationHelper.createActivation(activationType: activationType, useBiometry: true)
			XCTAssertTrue(session.hasBiometryFactor())
			XCTAssertEqual(session.setup?.applicationKey, server.applicationKey)
			XCTAssertEqual(session.setup?.applicationSecret, server.applicationSecret)
			XCTAssertEqual(session.activationIdentifier, activationHelper.activation.activationId)
			session.reset()
		}
    }
	
	func testCreateActivation() throws {
		try configureServerAndSession()
		try [ ActivationHelper.ActivationType.noCode, .code, .codeWithSignature ].forEach { activationType in
			try activationHelper.createActivation(activationType: activationType, useBiometry: false)
			XCTAssertFalse(session.hasBiometryFactor())
			XCTAssertEqual(session.setup?.applicationKey, server.applicationKey)
			XCTAssertEqual(session.setup?.applicationSecret, server.applicationSecret)
			XCTAssertEqual(session.activationIdentifier, activationHelper.activation.activationId)
			session.reset()
		}
	}
	
	func testWithNoRecoveryCodes() throws {
		try configureServerAndSession(config: MiniPAS.Config(enableRecovery: false, ctrLookAhead: 10))
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: true)
		XCTAssertFalse(session.hasActivationRecoveryData)
	}

	func testWithRecoveryCodes() throws {
		try configureServerAndSession(config: MiniPAS.Config(enableRecovery: true, ctrLookAhead: 10))
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: true)
		XCTAssertTrue(session.hasActivationRecoveryData)
		
		let encryptedVaultKey = try server.getEncryptedVaultKey(activationEntry: activationHelper.activation)
		let recoveryData = try session.activationRecoveryData(encryptedVaultKey: encryptedVaultKey, keys: activationHelper.possessionWithKnowledge)
		XCTAssertEqual(activationHelper.activation.recoveryCode, recoveryData.recoveryCode)
		XCTAssertEqual(activationHelper.activation.recoveryPuk, recoveryData.puk)
	}
	
	func testDecodeActivationStatus() throws {
		try configureServerAndSession()
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: true)
		var status = try activationHelper.getActivationStatus()
		XCTAssertEqual(.active, status.state)
		
		try server.blockActivation(entry: &activationHelper.activation)
		status = try activationHelper.getActivationStatus()
		XCTAssertEqual(.blocked, status.state)

		try server.unblockActivation(entry: &activationHelper.activation)
		status = try activationHelper.getActivationStatus()
		XCTAssertEqual(.active, status.state)
		
		XCTAssertTrue(try activationHelper.validatePassword(password: activationHelper.goodPassword))
		XCTAssertTrue(try activationHelper.validatePassword(password: activationHelper.goodPassword))
		
		// Save state
		let savedState = session.serializedState()
		
		// Now reset the activation and deserialize state
		session.reset()
		XCTAssertTrue(session.hasValidSetup)
		XCTAssertTrue(session.canStartActivation)
		XCTAssertFalse(session.hasPendingActivation)
		XCTAssertFalse(session.hasValidActivation)
		
		try session.deserialize(state: savedState)
		
		XCTAssertTrue(session.hasValidSetup)
		XCTAssertFalse(session.canStartActivation)
		XCTAssertFalse(session.hasPendingActivation)
		XCTAssertTrue(session.hasValidActivation)
		
		XCTAssertTrue(try activationHelper.validatePassword(password: activationHelper.goodPassword))
		
		// Remove activation
		try server.removeActivation(entry: &activationHelper.activation)
		status = try activationHelper.getActivationStatus()
		XCTAssertEqual(.removed, status.state)
	}
	
	// MARK: - Biometry -
	
	func testAddBiometryFactor() throws {
		try configureServerAndSession()
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: false)
		
		XCTAssertFalse(session.hasBiometryFactor())
		
		// Try to sign with biometry
		var result = try activationHelper.validateFactors(keys: activationHelper.possessionWithBiometry)
		XCTAssertFalse(result)
		
		let encryptedVaultKey = try server.getEncryptedVaultKey(activationEntry: activationHelper.activation)
		try session.addBiometryFactor(encryptedVaultKey: encryptedVaultKey, keys: activationHelper.possessionWithBiometry)
		
		XCTAssertTrue(session.hasBiometryFactor())
		result = try activationHelper.validateFactors(keys: activationHelper.possessionWithBiometry)
		XCTAssertTrue(result)
		
		try session.removeBiometryFactor()
		XCTAssertFalse(session.hasBiometryFactor())
	}
	
	// MARK: - ECDSA signatures -
	
	func testServerSignedData() throws {
		try configureServerAndSession()
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: true)
		
		let dataToSign = "This is very sensitive information.".data(using: .utf8)!
		let badData = "This 1s very sensitive information.".data(using: .utf8)!
		let signedData1 = try server.signDataWithMasterServerKey(data: dataToSign)
		let sd = SignedData()
		sd.signingDataKey = .ecdsa_MasterServerKey
		sd.data = dataToSign
		sd.signature = signedData1
		
		try session.verifyServerSignedData(signedData: sd)
		
		sd.signingDataKey = .ecdsa_PersonalizedKey
		sd.data = dataToSign
		sd.signature = try server.signDataWithServerKey(data: dataToSign, activationEntry: &activationHelper.activation)
		
		try session.verifyServerSignedData(signedData: sd)
		
		// Now use a bad data...
		do {
			sd.signingDataKey = .ecdsa_MasterServerKey
			sd.data = badData
			sd.signature = try server.signDataWithMasterServerKey(data: dataToSign)
			
			try session.verifyServerSignedData(signedData: sd)
		} catch {
			let error = error as NSError
			XCTAssertEqual(.wrongSignature, error.powerAuthCoreErrorCode)
		}
		do {
			sd.signingDataKey = .ecdsa_PersonalizedKey
			sd.data = badData
			sd.signature = try server.signDataWithServerKey(data: dataToSign, activationEntry: &activationHelper.activation)
			
			try session.verifyServerSignedData(signedData: sd)
		} catch {
			let error = error as NSError
			XCTAssertEqual(.wrongSignature, error.powerAuthCoreErrorCode)
		}
	}
	
	func testDeviceSignedData() throws {
		try configureServerAndSession()
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: true)
		
		let dataToSign = "This is very sensitive information.".data(using: .utf8)!
		let encryptedVaultKey = try server.getEncryptedVaultKey(activationEntry: activationHelper.activation)
		let signature = try session.signDataWithDevicePrivateKey(encryptedVaultKey: encryptedVaultKey, keys: activationHelper.possession, data: dataToSign)
		
		let result = try server.verifyDeviceSignedData(data: dataToSign, signature: signature, activationEntry: &activationHelper.activation)
		XCTAssertTrue(result)
	}
	
	// MARK: - PowerAuth signatures -
	
	func testOnlineSignature() throws {
		try configureServerAndSession()
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: true)
		
		for _ in 1...32 {
			try [ activationHelper.possession,
				  activationHelper.possessionWithBiometry,
				  activationHelper.possessionWithKnowledge,
				  activationHelper.possessionWithKnowledgeAndBiometry ]
				.forEach { signatureKeys in
					// Prepare data
					let dataToSign = try CryptoUtils.variableLengthRandomData()
					let method = [ "POST", "GET", "DELETE" ].randomElement()!
					let uriId = [ "/login", "/get/data", "/some/other/id" ].randomElement()!
					let httpData = HTTPRequestData(method: method, uri: uriId)
					httpData.body = dataToSign
					// Calculate signature on client
					let signature = try session.signHttpRequest(request: httpData, keys: signatureKeys)
					// Verify signature on server
					let request = MiniPAS.OnlineSignature(
						method: method,
						uriId: uriId,
						body: dataToSign,
						signature: signature.signature,
						version: signature.version,
						factor: signature.factor,
						nonce: signature.nonce,
						activationId: signature.activationId,
						applicationKey: signature.applicationKey)
					let result = try server.verify(onlineSignature: request, activationEntry: &activationHelper.activation)
					XCTAssertTrue(result == .ok)
					let status = try activationHelper.getActivationStatus()
					XCTAssertEqual(.active, status.state)
				}
		}
		// test wrong signatures
		XCTAssertFalse(try activationHelper.validatePassword(password: activationHelper.badPassword))
		XCTAssertFalse(try activationHelper.validateFactors(keys: SignatureFactorkKeys(possessionKey: try CryptoUtils.randomBytes(count: 16), biometryKey: nil, password: nil)))
		XCTAssertFalse(try activationHelper.validateFactors(keys: SignatureFactorkKeys(possessionKey: activationHelper.possessionKey, biometryKey: try CryptoUtils.randomBytes(count: 16), password: nil)))
		
		var status = try activationHelper.getActivationStatus()
		XCTAssertEqual(.active, status.state)
		XCTAssertEqual(3, status.failCount)
		
		XCTAssertTrue(try activationHelper.validatePassword(password: activationHelper.goodPassword))
		status = try activationHelper.getActivationStatus()
		XCTAssertEqual(.active, status.state)
		XCTAssertEqual(0, status.failCount)
	}
	
	func testOfflineSignature() throws {
		try configureServerAndSession()
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: true)
		
		for _ in 1...32 {
			try [ activationHelper.possession,
				  activationHelper.possessionWithBiometry,
				  activationHelper.possessionWithKnowledge ]
				.forEach { signatureKeys in
					// Prepare nonce
					let offlineNonce = try CryptoUtils.randomBytes(count: 16).base64EncodedString()
					// Prepare data
					let dataToSign = try CryptoUtils.variableLengthRandomData()
					let uriId = [ "/login", "/get/data", "/some/other/id" ].randomElement()!
					let httpData = HTTPRequestData(method: "POST", uri: uriId)
					httpData.body = dataToSign
					httpData.offlineNonce = offlineNonce
					// Calculate offline signature on client
					let clientSignature = try session.signHttpRequest(request: httpData, keys: signatureKeys)
					// Verify offline signature on server
					let request = MiniPAS.OfflineSignature(
						offlineNonce: offlineNonce,
						uriId: uriId,
						data: dataToSign,
						activationId: session.activationIdentifier ?? "",
						signature: clientSignature.signature,
						allowBiometry: true)
					let result = try server.verify(offlineSignature: request, activationEntry: &activationHelper.activation)
					XCTAssertTrue(result == .ok)
				}
		}
	}
	
	func testCounterSynchronization_Deadlock() throws {
		try configureServerAndSession()
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: true)
		
	}
}
