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
import CommonCrypto


/// The `MiniPASCrypto` implements a few cryptographic primitives required by PowerAuth protocol.
/// The class is useful for testing purposes only.
class MiniPASCrypto {
	
	enum CryptoErrors: Error {
		case invalidInputData
		case invalidInputDataSize
		case encryptionError
		case decryptionError
		case ecKeyExportFailed
	}
	
	static let ZERO_IV = Data(count: 16)
	
	// MARK: - protocol functions -
	
	/// KDF function, as defined by PowerAuth V2 & V3 protocol
	/// - Parameters:
	///   - key: Base key
	///   - index: Key derivation index
	/// - Throws: In case of failure
	/// - Returns: Derived key data
	static func KDF(key: Data, index: Int64) throws -> Data {
		var data = Data(count: 8)
		var indexBig = index.bigEndian
		let buffer = withUnsafeBytes(of: &indexBig, { Data($0) })
		data.append(buffer)
		return try AES_ECB_Encrypt(data: data, key: key, ivData: Data(count: 16))
	}
	
	/// KDF_Internal function, as defined by PowerAuth V2 & V3 protocol
	/// - Parameters:
	///   - key: Base key
	///   - index: Key derivation index
	/// - Returns: Derived key data
	static func KDF_Internal(key: Data, index: Data) throws -> Data {
		return try CONVERT_32Bto16B(key: HMAC_SHA256(key: key, data: index))
	}
	
	/// Reduce input 32 bytes long key into 16 bytes long key.
	/// - Parameter key: Input key
	/// - Throws: In case of invalid key provided
	/// - Returns: Reduced key material
	static func CONVERT_32Bto16B(key: Data) throws -> Data {
		guard key.count == 32 else {
			throw CryptoErrors.invalidInputDataSize
		}
		var out = Data(count: 16)
		for i in 0...15 {
			out[i] = key[i] ^ key[i + 16]
		}
		return out
	}
	
	/// Calculate decimalized activation fingerprint calculated from provided data.
	/// - Parameters:
	///   - serverPublicKey: Server's public key.
	///   - clientPublicKey: Device's public key.
	///   - activationId: Activation identifier
	/// - Throws: In case of failure
	/// - Returns: Decimnalized fingerprint from provided data.
	static func CalculateActivationFingerprint(serverPublicKey: ECKeyPair.KeyAgreement.PublicKey, clientPublicKey: ECKeyPair.KeyAgreement.PublicKey, activationId: String) throws -> String {
		guard let serverCompact = serverPublicKey.normalizedRepresentation else {
			throw CryptoErrors.ecKeyExportFailed
		}
		guard let clientCompact = clientPublicKey.normalizedRepresentation else {
			throw CryptoErrors.ecKeyExportFailed
		}
		guard let activationIdData = activationId.data(using: .ascii) else {
			throw CryptoErrors.invalidInputDataSize
		}
		let hashData = SHA256(data: clientCompact + activationIdData + serverCompact)
		return try CalculateDecimalizedSignature(data: hashData)
	}
	
	/// Just calculate decimalized signature from provided data.
	/// - Parameter data: Data to reduce to decimalized signature.
	/// - Throws: In case that insufficient data is provided.
	/// - Returns: Decimalized signature from provided data
	static func CalculateDecimalizedSignature(data: Data) throws -> String {
		guard data.count >= 4 else {
			throw CryptoErrors.invalidInputDataSize
		}
		let offset = data.count - 4
		let dbc = (
			(UInt(data[offset + 0] & 0x7F) << 24) |
			(UInt(data[offset + 1]) << 16) |
			(UInt(data[offset + 2]) << 8) |
			 UInt(data[offset + 3])
		) % 100000000
		return String(format:"%08u", dbc)
	}
	
	/// Calculate the next value for HASH based counter.
	/// - Parameter ctrData: Current hash based counter value
	/// - Throws: In case of failure
	/// - Returns: Next value for hash based counter
	static func NextCtrData(ctrData: Data) throws -> Data {
		return try CONVERT_32Bto16B(key: SHA256(data: ctrData))
	}
	
	
	// MARK: - HMAC & SHA256 -
	
	/// Calculate HMAC-SHA256 from given key and data.
	/// - Parameters:
	///   - key: MAC key
	///   - data: Data
	/// - Returns: HMAC-SHA256 from given data and key
	static func HMAC_SHA256(key: Data, data: Data) -> Data {
		let hmacKey = SymmetricKey(data: key)
		return Data(HMAC<SHA256>.authenticationCode(for: data, using: hmacKey))
	}
	
	/// Calculate SHA256 hash from given data.
	/// - Parameter data: Data to be hashed
	/// - Returns: Hash from given data
	static func SHA256(data: Data) -> Data {
		return Data(CryptoKit.SHA256.hash(data: data))
	}
	
	
	// MARK: - AES -
	
	/// Encrypt data with AES in ECB mode.
	/// - Parameters:
	///   - data: 16 bytes aligned data to encrypt.
	///   - key: Encryption key
	///   - ivData: IV data
	/// - Throws: In case of failure.
	/// - Returns: Encrypted data.
	static func AES_ECB_Encrypt(data: Data, key: Data, ivData: Data) throws -> Data {
		return try AES_Enc(data: data, key: key, ivData: ivData, options: kCCOptionECBMode)
	}
	
	/// Decrypt data with AES in ECB mode.
	/// - Parameters:
	///   - data: 16 bytes aligned encrypted data to encrypt.
	///   - key: Decryption key
	///   - ivData: IV data
	/// - Throws: In case of failure.
	/// - Returns: Decrypted data.
	static func AES_ECB_Decrypt(data: Data, key: Data, ivData: Data) throws -> Data {
		return try AES_Dec(data: data, key: key, ivData: ivData, options: kCCOptionECBMode)
	}

	/// Encrypt data with AES in CBC mode, with PKCS7 padding.
	/// - Parameters:
	///   - data: Data to encrypt.
	///   - key: Encryption key
	///   - ivData: IV data
	/// - Throws: In case of failure.
	/// - Returns: Encrypted data.
	static func AES_CBC_PKCS7_Encrypt(data: Data, key: Data, ivData: Data) throws -> Data {
		return try AES_Enc(data: data, key: key, ivData: ivData, options: kCCOptionPKCS7Padding)
	}

	/// Decrypt data with AES in CBC mode, with PKCS7 padding.
	/// - Parameters:
	///   - data: Data to decrypt.
	///   - key: Decryption key
	///   - ivData: IV data
	/// - Throws: In case of failure.
	/// - Returns: Decrypted data.
	static func AES_CBC_PKCS7_Decrypt(data: Data, key: Data, ivData: Data) throws -> Data {
		return try AES_Dec(data: data, key: key, ivData: ivData, options: kCCOptionPKCS7Padding)
	}
	
	/// Encrypt data with AES in CBC mode, with NO padding.
	/// - Parameters:
	///   - data: Data to encrypt.
	///   - key: Encryption key
	///   - ivData: IV data
	/// - Throws: In case of failure.
	/// - Returns: Encrypted data.
	static func AES_CBC_Encrypt(data: Data, key: Data, ivData: Data) throws -> Data {
		return try AES_Enc(data: data, key: key, ivData: ivData, options: 0)
	}
	
	/// Low level AES encrypt implementation.
	/// - Parameters:
	///   - data: Data to encrypt or decrypt.
	///   - key: Encryption or decryption key.
	///   - ivData: IV data
	///   - mode: Options, use `CCOptions` constants.
	/// - Throws: In case of failure.
	/// - Returns: Encrypted or decrypted data.
	private static func AES_Enc(data: Data, key: Data, ivData: Data, options: Int) throws -> Data {
		
		let count: Int
		if options == kCCOptionECBMode {
			count = data.count
		} else {
			count = data.count + kCCBlockSizeAES128
		}
		
		var cryptData = Data(count: count)
		var numBytesEncrypted: size_t = 0

		let result = cryptData.withUnsafeMutableBytes { cryptBytes in
			data.withUnsafeBytes { dataBytes in
				ivData.withUnsafeBytes { ivBytes in
					key.withUnsafeBytes { keyBytes in
						CCCrypt(CCOperation(kCCEncrypt),
								  CCAlgorithm(kCCAlgorithmAES),
								  CCOptions(options),
								  keyBytes.baseAddress, keyBytes.count,
								  ivBytes.baseAddress,
								  dataBytes.baseAddress, dataBytes.count,
								  cryptBytes.baseAddress, cryptBytes.count,
								  &numBytesEncrypted)
					}
				}
			}
		}
		if result != kCCSuccess {
			throw CryptoErrors.encryptionError
		}
		cryptData.count = numBytesEncrypted
		return cryptData;
	}
	
	/// Low level AES decrypt implementation.
	/// - Parameters:
	///   - data: Data to encrypt or decrypt.
	///   - key: Encryption or decryption key.
	///   - ivData: IV data
	///   - mode: Options, use `CCOptions` constants.
	/// - Throws: In case of failure.
	/// - Returns: Encrypted or decrypted data.
	private static func AES_Dec(data: Data, key: Data, ivData: Data, options: Int) throws -> Data {
		
		let count: Int
		if options == kCCOptionECBMode {
			count = data.count
		} else {
			count = data.count
		}
		
		var plainData = Data(count: count)
		var numBytesDecrypted: size_t = 0

		let result = plainData.withUnsafeMutableBytes { plainBytes in
			data.withUnsafeBytes { dataBytes in
				ivData.withUnsafeBytes { ivBytes in
					key.withUnsafeBytes { keyBytes in
						CCCrypt(CCOperation(kCCDecrypt),
								  CCAlgorithm(kCCAlgorithmAES),
								  CCOptions(options),
								  keyBytes.baseAddress, keyBytes.count,
								  ivBytes.baseAddress,
								  dataBytes.baseAddress, dataBytes.count,
								  plainBytes.baseAddress, plainBytes.count,
								  &numBytesDecrypted)
					}
				}
			}
		}
		if result != kCCSuccess {
			throw CryptoErrors.decryptionError
		}
		plainData.count = numBytesDecrypted
		return plainData;
	}
}
