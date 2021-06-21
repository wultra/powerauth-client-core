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

class ActivationHelper {
    
    let server: MiniPAS
    let session: Session
    var activation: MiniPAS.ActivationEntry!
    
    var possessionKey: Data!
    var biometryKey: Data!
    var goodPassword = Password(string: "hellow0rld")
    let badPassword = Password(string: "nbusr123")
    
    var possession: SignatureFactorkKeys {
        return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: nil, password: nil)
    }
    
    var possessionWithBiometry: SignatureFactorkKeys {
        return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: biometryKey, password: nil)
    }
    
    var possessionWithKnowledge: SignatureFactorkKeys {
        return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: nil, password: goodPassword)
    }
    
    var possessionWithKnowledgeAndBiometry: SignatureFactorkKeys {
        return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: biometryKey, password: goodPassword)
    }
    
    var possessionWithBadKnowledge: SignatureFactorkKeys {
        return SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: nil, password: badPassword)
    }
    
    init(server: MiniPAS, session: Session) {
        self.server = server
        self.session = session
        self.possessionKey = try? CryptoUtils.randomBytes(count: 16)
        self.biometryKey = try? CryptoUtils.randomBytes(count: 16)
    }
    
    //
    enum ActivationError: Error {
        case invalidState
        case badActivationFingerprint
    }
    
    /// Defines how activation will be created.
    enum ActivationType {
        /// With no activation code
        case noCode
        /// With activation code
        case code
        /// With sigend activation code
        case codeWithSignature
    }
    
    /// Function create activation in fake MiniPAS server.
    /// - Parameters:
    ///   - activationType: How activation should be created
    ///   - useBiometry: true if activation has configured biometry out of the box
    /// - Throws: In case of failure
    /// - Returns: `MiniPAS.ActivationEntry` structure that can be used later for other tests
    func createActivation(activationType: ActivationType, useBiometry: Bool) throws {

        guard session.hasValidActivation == false &&
                session.canStartActivation == true &&
                session.hasPendingActivation == false  else {
            throw ActivationError.invalidState
        }
        
        // Prepare activation on server
        var activationEntry = try server.prepareActivation()
        
        // Initiate activation on client's side
        let startParam: StartActivationParam
        switch activationType {
        case .noCode:
            startParam = StartActivationParam()
        case .code:
            startParam = StartActivationParam(activationCode: ActivationCodeUtil.parse(fromActivationCode: activationEntry.activationCode))
        case .codeWithSignature:
            startParam = StartActivationParam(activationCode: ActivationCodeUtil.parse(fromActivationCode: activationEntry.activationCode + "#" + activationEntry.activationCodeSignature))
        }
        let startResult = try session.startActivation(with: startParam)
        
        guard session.hasValidActivation == false &&
                session.canStartActivation == false &&
                session.hasPendingActivation == true  else {
            throw ActivationError.invalidState
        }
        
        // Pair activation on server's side
        let serverRequest = MiniPAS.ActivationRequest(devicePublicKey: startResult.devicePublicKey, nextState: .active)
        let serverResponse = try server.activate(request: serverRequest, entry: &activationEntry)
        
        // Pair activation on client's side
        let validateParam = serverResponse.toClientParam()
        let validateResult = try session.validateActivationResponse(response: validateParam)
        guard validateResult.activationFingerprint == activationEntry.activationFingerprint else {
            throw ActivationError.badActivationFingerprint
        }
        
        // Complete activation with desired combination of keys
        try session.completeActivation(withKeys: useBiometry ? possessionWithKnowledgeAndBiometry : possessionWithKnowledge)
        
        guard session.hasValidActivation == true &&
                session.canStartActivation == false &&
                session.hasPendingActivation == false  else {
            throw ActivationError.invalidState
        }
        
        self.activation = activationEntry
    }
    
    /// Function get activation status from fake MiniPAS server.
    /// - Parameter activationEntry: Activation entry
    /// - Throws: In case of failure
    /// - Returns: Decoded activation status
    func getActivationStatus() throws -> ActivationStatus {
        // Prepare challenge 
        let challenge = try CryptoUtils.randomBytes(count: 16).base64EncodedString()
        // Get encrypted status from the server
        let (status, nonce) = try server.getEncryptedStatus(challenge: challenge, entry: &activation)
        // Decrypt status on client
        return try session.decode(encryptedStatus: EncryptedActivationStatus(challenge: challenge, statusBlob: status, nonce: nonce), keys: possession)
    }
    
    /// Change password to new one. The password is changed in session and also in `goodPassword` variable,
    /// so the next access to knowledge factor will return this new password.
    ///
    /// - Parameter newPassword: New password
    /// - Throws: In case of failure
    func changePassword(newPassword: String) throws {
        let newPassword = Password(string: newPassword)
        try session.changeUserPassword(old: goodPassword, new: newPassword)
        goodPassword = newPassword
    }
    
    
    /// Validate password by computing signature on the server.
    /// - Parameter password: Password to validate
    /// - Throws: In case of failure
    /// - Returns: true if password is valid
    func validatePassword(password: Password) throws -> Bool {
        do {
            let keys = SignatureFactorkKeys(possessionKey: possessionKey, biometryKey: nil, password: password)
            let clientSignature = try session.signHttpRequest(request: HTTPRequestData(method: "POST", uri: "/password/validate"), keys: keys)
            let serverSignature = MiniPAS.OnlineSignature(
                method: "POST",
                uriId: "/password/validate",
                body: Data(),
                signature: clientSignature.signature,
                version: clientSignature.version,
                factor: clientSignature.factor,
                nonce: clientSignature.nonce,
                activationId: clientSignature.activationId,
                applicationKey: clientSignature.applicationKey)
            let result = try server.verify(onlineSignature: serverSignature, activationEntry: &activation)
            return result == .ok
        } catch {
            print("ActivationHelper.validatePassword: Failed: \(error.localizedDescription)")
            return false
        }
    }
    
    /// Validate signature factor keys by computing signature on the server.
    /// - Parameter keys: Signature factors to validate
    /// - Throws: In case of failure
    /// - Returns: true if password is valid
    func validateFactors(keys: SignatureFactorkKeys, for data: Data = Data()) throws -> Bool {
        do {
            let clientSignature = try session.signHttpRequest(request: HTTPRequestData(method: "POST", uri: "/validate/keys"), keys: keys)
            let serverSignature = MiniPAS.OnlineSignature(
                method: "POST",
                uriId: "/validate/keys",
                body: data,
                signature: clientSignature.signature,
                version: clientSignature.version,
                factor: clientSignature.factor,
                nonce: clientSignature.nonce,
                activationId: clientSignature.activationId,
                applicationKey: clientSignature.applicationKey)
            let result = try server.verify(onlineSignature: serverSignature, activationEntry: &activation)
            return result == .ok
        } catch {
            print("ActivationHelper.validateFactors: Failed: \(error.localizedDescription)")
            return false
        }
    }
}

extension SignatureFactorkKeys {
    
    /// Returns string representation of combination of factor keys.
    var stringRepresentation: String {
        var components = [String]()
        if !possessionKey.isEmpty {
            components.append("possession")
        }
        if password != nil {
            components.append("knowledge")
        }
        if biometryKey != nil {
            components.append("biometry")
        }
        return components.joined(separator: "_")
    }
}

extension CryptoUtils {
    
    /// Return random data with variable length.
    /// - Parameter minimumLength: Minimum random data length.
    /// - Throws: In case of failure
    /// - Returns: Returns random data with variable length
    static func variableLengthRandomData(from minimumLength: UInt = 13) throws -> Data {
        let count = UInt(try randomBytes(count: 1)[0]) + minimumLength
        return try randomBytes(count: count)
    }
}
