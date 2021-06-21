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
    
    
    /// ECIES cryptogram for communication with the client
    struct EciesCryptogram {
        let body: String?
        let mac: String?
        let key: String?
        let nonce: String?
    }
    
    
    /// Class implementing ECIES scheme
    class EciesServerDecryptor {
        
        /// Set of keys required for ECIES cheme
        private struct EnvelopeKey {
            let encKey: Data
            let macKey: Data
            let ivKey: Data
        }
        
        let privateKey: ECKeyPair.KeyAgreement
        let sharedInfo1: Data
        let sharedInfo2: Data
        
        private var envelopeKey: EnvelopeKey
        private var lastIV: Data
    
        
        /// Initialize object with private key and pre-agreed constants.
        /// - Parameters:
        ///   - privateKey: Private key to derive ephemeral shared secret
        ///   - sh1: SharedInfo1 constant
        ///   - sh2: SharedInfo2 constant
        init(privateKey: ECKeyPair.KeyAgreement, sh1: Data, sh2: Data) {
            self.privateKey = privateKey
            self.sharedInfo1 = sh1
            self.sharedInfo2 = sh2
            self.envelopeKey = EnvelopeKey(encKey: Data(), macKey: Data(), ivKey: Data())
            self.lastIV = Data()
        }
        
        
        /// Decrypt request received from the client.
        /// - Parameter requestCryptogram: Request cryptogram
        /// - Throws: In case of failure
        /// - Returns: Decrypted data
        func decrypt(requestCryptogram: EciesCryptogram) throws -> Data {
            guard let nonce = requestCryptogram.nonce,
                  let mac = requestCryptogram.mac,
                  let body = requestCryptogram.body,
                  let key = requestCryptogram.key else {
                throw PASErrors.invalidParameter
            }
            guard let nonceData = Data(base64Encoded: nonce),
                  let macData = Data(base64Encoded: mac),
                  let bodyData = Data(base64Encoded: body),
                  let keyData = Data(base64Encoded: key) else {
                throw PASErrors.invalidBase64Data
            }
            envelopeKey = try deriveEnvelopeKey(publicKey: keyData)
            
            let expectedMac = MiniPASCrypto.HMAC_SHA256(key: envelopeKey.macKey, data: bodyData + sharedInfo2)
            if expectedMac != macData {
                throw PASErrors.eciesWrongMac
            }
            lastIV = try MiniPASCrypto.KDF_Internal(key: envelopeKey.ivKey, index: nonceData)
            return try MiniPASCrypto.AES_CBC_PKCS7_Decrypt(data: bodyData, key: envelopeKey.encKey, ivData: lastIV)
        }
        
        
        /// Encrypt response data to response cryptogram.
        /// - Parameter responseData: Data to encrypt
        /// - Throws: In case of failure
        /// - Returns: Cryptogram with response data
        func encrypt(responseData: Data) throws -> EciesCryptogram {
            guard !lastIV.isEmpty else {
                throw PASErrors.eciesWrongState
            }
            let encryptedResponse = try MiniPASCrypto.AES_CBC_PKCS7_Encrypt(data: responseData, key: envelopeKey.encKey, ivData: lastIV)
            let mac =  MiniPASCrypto.HMAC_SHA256(key: envelopeKey.macKey, data: encryptedResponse + sharedInfo2)
            let response = EciesCryptogram(
                body: encryptedResponse.base64EncodedString(),
                mac: mac.base64EncodedString(),
                key: nil,
                nonce: nil)
            lastIV.removeAll()
            return response
        }
        
        
        /// Derive envelope key from given public key.
        /// - Parameter publicKey: Ephemeral public key to derive shared secret
        /// - Throws: In case of failure
        /// - Returns: Envelove key required for data encryption and decryption
        private func deriveEnvelopeKey(publicKey: Data) throws -> EnvelopeKey {
            let info = sharedInfo1 + publicKey
            let keyBase = try privateKey.sharedSecret(with: publicKey)
            let keySecret = keyBase.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: info, outputByteCount: 48).dataBytes
            return EnvelopeKey(
                encKey: Data(keySecret[0..<16]),
                macKey: Data(keySecret[16..<32]),
                ivKey: Data(keySecret[32..<48])
            )
        }
    }
    
    /// Get application scoped ECIES encryptor
    /// - Parameter sharedInfo1: Pre-agreed sharedInfo1 constant
    /// - Throws: In case of failure
    /// - Returns: ECIES encryptor configured for application scope
    func getEciesEncryptorForApplicationScope(sharedInfo1: String) throws -> EciesServerDecryptor {
        guard let sharedInfo1Data = sharedInfo1.data(using: .utf8) else {
            throw PASErrors.invalidParameter
        }
        let sharedInfo2Data = MiniPASCrypto.SHA256(data: applicationSecret.data(using: .ascii)!)
        return EciesServerDecryptor(
            privateKey: try masterServerKeyPair.keyAgreement(),
            sh1: sharedInfo1Data,
            sh2: sharedInfo2Data)
    }
    
    
    /// Get activation scoped ECIES encryptor
    /// - Parameters:
    ///   - sharedInfo1: Pre-agreed sharedInfo1 constant
    ///   - activationEntry: Activation entry
    /// - Throws: In case of failure
    /// - Returns: Activation scoped ECIES encryptor
    func getEciesEncryptorForActivationScope(sharedInfo1: String, activationEntry: ActivationEntry) throws -> EciesServerDecryptor {
        guard let sharedInfo1Data = sharedInfo1.data(using: .utf8) else {
            throw PASErrors.invalidParameter
        }
        let sharedInfo2Data = MiniPASCrypto.HMAC_SHA256(key: activationEntry.keys.transportKey, data: applicationSecret.data(using: .ascii)!)
        return EciesServerDecryptor(
            privateKey: try activationEntry.serverKeyPair.keyAgreement(),
            sh1: sharedInfo1Data,
            sh2: sharedInfo2Data)
    }
}
