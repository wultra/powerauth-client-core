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

class EciesEncryptorTests: XCTestCase {

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
    
    func testApplicationScopeEncryptor() throws {
        try configureServerAndSession()
        let serverEncryptor = try server.getEciesEncryptorForApplicationScope(sharedInfo1: "/test/constant")
        for i in 1...20 {
            let dataToEncrypt = try CryptoUtils.variableLengthRandomData()
            // Encrypt data on client
            let encryptor = try session.eciesEncryptor(forScope: .application, keys: nil, sharedInfo1: "/test/constant".data(using: .ascii)!)
            XCTAssertTrue(encryptor.canEncryptRequest)
            XCTAssertFalse(encryptor.canDecryptResponse)
            let cryptogram = try encryptor.encrypt(requestData: dataToEncrypt)
            // Decrypt data on server
            let serverRequest = MiniPAS.EciesCryptogram(body: cryptogram.bodyBase64, mac: cryptogram.macBase64, key: cryptogram.keyBase64, nonce: cryptogram.nonceBase64)
            let serverRequestData = try serverEncryptor.decrypt(requestCryptogram: serverRequest)
            XCTAssertEqual(dataToEncrypt, serverRequestData)
            // Encrypt response on server
            let dataToResponse = try CryptoUtils.variableLengthRandomData()
            let serverCryptogram = try serverEncryptor.encrypt(responseData: dataToResponse)
            let clientResponseCryptogram = EciesCryptogram()
            clientResponseCryptogram.bodyBase64 = serverCryptogram.body
            clientResponseCryptogram.macBase64 = serverCryptogram.mac
            // Decrypt response on client
            let clientResponseData = try encryptor.decrypt(responseData: clientResponseCryptogram)
            XCTAssertEqual(dataToResponse, clientResponseData)
            
            if i == 5 {
                // create activation in the middle of the test
                try activationHelper.createActivation(activationType: .code, useBiometry: true)
            }
        }
    }
    
    func testActivationScopeEncryptor() throws {
        try configureServerAndSession()
        // At first, try access activation scoped encryptor without an activation
        let failedEncryptor = try? session.eciesEncryptor(forScope: .activation, keys: activationHelper.possession, sharedInfo1: "/test/after/activation".data(using: .ascii)!)
        XCTAssertNil(failedEncryptor)
        
        // Now create activation
        try activationHelper.createActivation(activationType: .code, useBiometry: true)
        let serverEncryptor = try server.getEciesEncryptorForActivationScope(sharedInfo1: "/test/after/activation", activationEntry: activationHelper.activation)
        for _ in 1...10 {
            let dataToEncrypt = try CryptoUtils.variableLengthRandomData()
            // Encrypt data on client
            let encryptor = try session.eciesEncryptor(forScope: .activation, keys: activationHelper.possession, sharedInfo1: "/test/after/activation".data(using: .ascii)!)
            XCTAssertTrue(encryptor.canEncryptRequest)
            XCTAssertFalse(encryptor.canDecryptResponse)
            let cryptogram = try encryptor.encrypt(requestData: dataToEncrypt)
            // Decrypt data on server
            let serverRequest = MiniPAS.EciesCryptogram(body: cryptogram.bodyBase64, mac: cryptogram.macBase64, key: cryptogram.keyBase64, nonce: cryptogram.nonceBase64)
            let serverRequestData = try serverEncryptor.decrypt(requestCryptogram: serverRequest)
            XCTAssertEqual(dataToEncrypt, serverRequestData)
            // Encrypt response on server
            let dataToResponse = try CryptoUtils.variableLengthRandomData()
            let serverCryptogram = try serverEncryptor.encrypt(responseData: dataToResponse)
            let clientResponseCryptogram = EciesCryptogram()
            clientResponseCryptogram.bodyBase64 = serverCryptogram.body
            clientResponseCryptogram.macBase64 = serverCryptogram.mac
            // Decrypt response on client
            let clientResponseData = try encryptor.decrypt(responseData: clientResponseCryptogram)
            XCTAssertEqual(dataToResponse, clientResponseData)
        }
    }
}
