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

    override func setUpWithError() throws {
    }

    override func tearDownWithError() throws {
    }

    func testSwiftIntegration() throws {
		let setup = SessionSetup(applicationKey: "", applicationSecret: "", masterServerPublicKey: "", sessionIdentifier: 0, externalEncryptionKey: nil)
		let session = Session(setup: setup)
		XCTAssertFalse(session.hasValidSetup)
		do {
			_ = try session.startActivation(with: StartActivationParam())
			XCTFail("Should never go here")
		} catch {
			let error = error as NSError
			XCTAssertEqual(error.powerAuthCoreErrorCode, .wrongState)
		}
    }
}
