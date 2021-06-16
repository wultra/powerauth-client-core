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
	}
	
	func testDecodeActivationStatus() throws {
		try configureServerAndSession()
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: true)
		var status = try activationHelper.getActivationStatus()
		XCTAssertEqual(.active, status.state)
		server.blockActivation(entry: &activationHelper.activation)
		status = try activationHelper.getActivationStatus()
		XCTAssertEqual(.blocked, status.state)
		server.removeActivation(entry: &activationHelper.activation)
		status = try activationHelper.getActivationStatus()
		XCTAssertEqual(.removed, status.state)
		// Now reset the activation
		session.reset()
		XCTAssertTrue(session.hasValidSetup)
		XCTAssertTrue(session.canStartActivation)
		XCTAssertFalse(session.hasPendingActivation)
		XCTAssertFalse(session.hasValidActivation)
	}
	
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
	
	func testOnlineSignature() throws {
		try configureServerAndSession()
		try activationHelper.createActivation(activationType: .codeWithSignature, useBiometry: true)
		
		try [ activationHelper.possession,
			  activationHelper.possessionWithBiometry,
			  activationHelper.possessionWithKnowledge ]
			.forEach { signatureKeys in
				let dataLength = 18 + UInt(try CryptoUtils.randomBytes(count: 1)[0])
				let dataToSign = try CryptoUtils.randomBytes(count: dataLength)
				let method = [ "POST", "GET", "DELETE" ].randomElement()!
				let uriId = [ "/login", "/get/data", "/some/other/id" ].randomElement()!
				let httpData = HTTPRequestData(method: method, uri: uriId)
				httpData.body = dataToSign
				let signature = try session.signHttpRequest(request: httpData, keys: signatureKeys)
				let serverSignature = MiniPAS.OnlineSignature(
					method: method,
					uriId: uriId,
					body: dataToSign,
					signature: signature.signature,
					version: signature.version,
					factor: signature.factor,
					nonce: signature.nonce,
					activationId: signature.activationId,
					applicationKey: signature.applicationKey)
				let result = try server.verify(onlineSignature: serverSignature, activationEntry: &activationHelper.activation)
				XCTAssertTrue(result == .ok)
			}
	}
}
