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

/// Class representing EC key-pair.
class ECKeyPair {
    
    let privateKey: Data        // RAW representation
    let publicKey: Data         // X9.63 representation
    
    init() {
        let pk = P256.KeyAgreement.PrivateKey(compactRepresentable: true)
        privateKey = pk.rawRepresentation
        publicKey = pk.publicKey.x963Representation
    }
    
    init(privateKey: Data, publicKey: Data) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
    
    /// Type representing EC key-pair for signature calculations.
    struct Signing {
        typealias PublicKey = P256.Signing.PublicKey
        typealias PrivateKey = P256.Signing.PrivateKey
        
        let publicKey: PublicKey
        let privateKey: PrivateKey
    }
    
    
    /// Prepare KeyPair for data signing purposes.
    /// - Throws: In case of failure.
    /// - Returns: Key-pair for signature calculations.
    func signing() throws -> Signing {
        let publicKey = try Signing.PublicKey(x963Representation: publicKey)
        let privateKey = try Signing.PrivateKey(rawRepresentation: privateKey)
        return Signing(publicKey: publicKey, privateKey: privateKey)
    }
    
    
    /// Type representing EC key-pair for key agreement computations.
    struct KeyAgreement {
        typealias PublicKey = P256.KeyAgreement.PublicKey
        typealias PrivateKey = P256.KeyAgreement.PrivateKey
        let publicKey: PublicKey
        let privateKey: PrivateKey
    }
    
    
    /// Prepare KeyPair for key agreement computations.
    /// - Throws: In case of failure.
    /// - Returns: Key-pair for key agreement computation.
    func keyAgreement() throws -> KeyAgreement {
        let publicKey = try KeyAgreement.PublicKey(x963Representation: publicKey)
        let privateKey = try KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        return KeyAgreement(publicKey: publicKey, privateKey: privateKey)
    }
}


extension ECKeyPair.Signing {
    
    /// Compute ECDSA signature from given data.
    /// - Parameter data: Data to sign
    /// - Throws: In case of failure.
    /// - Returns: ECDSA signature from given data
    func sign(data: Data) throws -> Data {
        let signature = try privateKey.signature(for: data)
        return signature.derRepresentation
    }
    
    /// Validate ECDSA signature
    /// - Parameters:
    ///   - signature: Signature data
    ///   - data: Signed data
    /// - Throws: In caae of failure.
    /// - Returns: true if signature is valid
    func isValid(signature: Data, for data: Data) throws -> Bool {
        let signature = try P256.Signing.ECDSASignature(derRepresentation: signature)
        return publicKey.isValidSignature(signature, for: data)
    }
    
    /// Import public key
    /// - Parameter publicKeyData: Public key data.
    /// - Throws: In case of failure
    /// - Returns: Imported key
    static func importKey(publicKeyData: Data) throws -> ECKeyPair.Signing.PublicKey {
        return try P256.Signing.PublicKey(x963Representation: publicKeyData)
    }
}

extension ECKeyPair.KeyAgreement {
    
    /// Derive ECDSA shared secret
    /// - Parameter publicKeyData: Other side's public key.
    /// - Throws: In case of failure.
    /// - Returns: Shared secret
    func sharedSecret(with publicKeyData: Data) throws -> SharedSecret {
        let publicKey = try ECKeyPair.KeyAgreement.importKey(publicKeyData: publicKeyData)
        return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
    }
    
    /// Import public key
    /// - Parameter publicKeyData: Public key data.
    /// - Throws: In case of failure
    /// - Returns: Imported key
    static func importKey(publicKeyData: Data) throws -> ECKeyPair.KeyAgreement.PublicKey {
        return try P256.KeyAgreement.PublicKey(x963Representation: publicKeyData)
    }
}

extension ECKeyPair.KeyAgreement.PublicKey {
    
    /// Return public key representation in normalized form, required by PowerAuth protocol.
    var normalizedRepresentation: Data? {
        // This is equal to "compact", but "compact" representation is unavailable for imported public keys
        let raw = self.rawRepresentation
        // First 32 bytes from "raw representation" is X and that's what we need.
        guard raw.count >= 32 else {
            return nil
        }
        guard let start = raw.firstIndex(where: { $0 != 0x00 }) else {
            return nil
        }
        let end = raw.startIndex.advanced(by: 31)
        return raw.subdata(in: Range(start...end))
    }
}

extension SharedSecret {
    /// Raw bytes of shared secret
    var dataBytes: Data {
        return withUnsafeBytes { buffer in
            return Data(bytes: buffer.baseAddress!, count: buffer.count)
        }
    }
}

extension Data {
    
    /// Hexadecimal representation
    var hexDescription: String {
        return reduce("") {$0 + String(format: "%02x", $1)}
    }
}

extension SymmetricKey {
    /// Raw bytes of symmetric key
    var dataBytes: Data {
        return withUnsafeBytes { buffer in
            return Data(bytes: buffer.baseAddress!, count: buffer.count)
        }
    }
}
