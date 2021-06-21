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

/// The `MiniPAS` class simulates PowerAuth server counterpart with using
/// CryptoKit framework.
class MiniPAS {
    
    enum PASErrors: Error {
        case invalidParameter
        case invalidPublicKey
        case invalidBase64Data
        case invalidRandomGenerator
        case invalidActivationState
        case invalidApplicationKey
        case invalidActivationId
        
        case eciesWrongMac
        case eciesDecryption
        case eciesWrongState
    }
    
    struct Config {
        let enableRecovery: Bool
        let ctrLookAhead: UInt8
        
        static let `default` = Config (
            enableRecovery: true,
            ctrLookAhead: 10
        )
    }
    /// Master server key-pair
    let masterServerKeyPair: ECKeyPair
    
    /// Application key constant
    let applicationKey: String
    
    /// Application secret constant
    let applicationSecret: String
    
    /// Server's config
    let config: Config
    
    /// Class constructor.
    private init(masterServerKeyPair: ECKeyPair, applicationKey: String, applicationSecret: String, config: Config) {
        self.masterServerKeyPair = masterServerKeyPair
        self.applicationKey = applicationKey
        self.applicationSecret = applicationSecret
        self.config = config
    }
    
    /// Create fake PowerAuth server with given config.
    /// - Parameter config: Configuration for fake server.
    /// - Throws: In case of failure.
    /// - Returns: `MiniPAS` instance.
    static func craete(with config: Config) throws -> MiniPAS {
        let kp = ECKeyPair()
        let appKey = try CryptoUtils.randomBytes(count: 16).base64EncodedString()
        let appSecret = try CryptoUtils.randomBytes(count: 16).base64EncodedString()
        return MiniPAS(
            masterServerKeyPair: kp,
            applicationKey: appKey,
            applicationSecret: appSecret,
            config: config)
    }
    
    
    /// Return master server public key in Base64 encoded string
    var masterServerPublicKey: String {
        return masterServerKeyPair.publicKey.base64EncodedString()
    }
    
    /// Get session setup preconfigured with parameters from this server and with or without EEK.
    func getSessionSetup(eek: Data? = nil) -> SessionSetup {
        return SessionSetup(
            applicationKey: applicationKey,
            applicationSecret: applicationSecret,
            masterServerPublicKey: masterServerPublicKey,
            sessionIdentifier: 0,
            externalEncryptionKey: eek)
    }
}
