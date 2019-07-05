//
//  AES.swift
//  Kidega
//
//  Created by Mehmet Özçapkın on 4.07.2019.
//  Copyright © 2019 KLE Teknoloji A.Ş. All rights reserved.
//

import UIKit
import CommonCrypto

struct AES {
    
    static private let initializationVectorSize: Int = kCCBlockSizeAES128
    static private let options: CCOptions = CCOptions(kCCOptionPKCS7Padding)
    
}

// MARK: - Error

extension AES {
    
    enum Error: Swift.Error {
        case invalidKey
        case invalidKeySize
        case generateRandomIVFailed
        case encryptionFailed
        case decryptionFailed
    }
    
}

// MARK: - Public Methods

extension AES {
    
    static func encrypt(data: Data) throws -> Data {
        
        let bufferSize: Int = initializationVectorSize + data.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        try generateRandomInitializationVector(for: &buffer)
        
        var encryptedBytesCount: Int = 0
        
        do {
            
            let key = try self.key()
            try key.withUnsafeBytes { keyBytes in
                try data.withUnsafeBytes { dataBytes in
                    try buffer.withUnsafeMutableBytes { bufferBytes in
                        
                        guard
                            let keyBytesBaseAddress = keyBytes.baseAddress,
                            let dataBytesBaseAddress = dataBytes.baseAddress,
                            let bufferBytesBaseAddress = bufferBytes.baseAddress
                            else {
                                throw Error.encryptionFailed
                        }
                        
                        let status: CCCryptorStatus = CCCrypt(CCOperation(kCCEncrypt),
                                                              CCAlgorithm(kCCAlgorithmAES),
                                                              options,
                                                              keyBytesBaseAddress,
                                                              key.count,
                                                              bufferBytesBaseAddress,
                                                              dataBytesBaseAddress,
                                                              dataBytes.count,
                                                              bufferBytesBaseAddress + initializationVectorSize,
                                                              bufferSize,
                                                              &encryptedBytesCount)
                        
                        guard status == CCCryptorStatus(kCCSuccess) else {
                            throw Error.encryptionFailed
                        }
                        
                    }
                }
            }
            
        } catch {
            throw Error.encryptionFailed
        }
        
        let encryptedData: Data = buffer[..<(encryptedBytesCount + initializationVectorSize)]
        return encryptedData
        
    }
    
    static func decrypt(data: Data) throws -> Data {
        
        let bufferSize: Int = data.count - initializationVectorSize
        var buffer = Data(count: bufferSize)
        
        var numberBytesDecrypted: Int = 0
        
        do {
            let key = try self.key()
            try key.withUnsafeBytes { keyBytes in
                try data.withUnsafeBytes { dataToDecryptBytes in
                    try buffer.withUnsafeMutableBytes { bufferBytes in
                        
                        guard let keyBytesBaseAddress = keyBytes.baseAddress,
                            let dataToDecryptBytesBaseAddress = dataToDecryptBytes.baseAddress,
                            let bufferBytesBaseAddress = bufferBytes.baseAddress else {
                                throw Error.encryptionFailed
                        }
                        
                        let cryptStatus: CCCryptorStatus = CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES128),
                            options,
                            keyBytesBaseAddress,
                            key.count,
                            dataToDecryptBytesBaseAddress,
                            dataToDecryptBytesBaseAddress + initializationVectorSize,
                            bufferSize,
                            bufferBytesBaseAddress,
                            bufferSize,
                            &numberBytesDecrypted
                        )
                        
                        guard cryptStatus == CCCryptorStatus(kCCSuccess) else {
                            throw Error.decryptionFailed
                        }
                    }
                }
            }
        } catch {
            throw Error.encryptionFailed
        }
        
        let decryptedData: Data = buffer[..<numberBytesDecrypted]
        
        return decryptedData
        
    }
    
}

// MARK: - Private Methods

extension AES {
    
    static private func key() throws -> Data {
        
        guard let uuid = UIDevice.current.identifierForVendor?.uuidString.components(separatedBy: "-").joined() else {
            throw Error.invalidKey
        }
        
        guard uuid.count == kCCKeySizeAES256 else {
            throw Error.invalidKeySize
        }
        
        return Data(uuid.utf8)
        
    }
    
    static private func generateRandomInitializationVector(for data: inout Data) throws {
        
        try data.withUnsafeMutableBytes { dataBytes in
            
            guard let dataBytesBaseAddress = dataBytes.baseAddress else {
                throw Error.generateRandomIVFailed
            }
            
            let status: Int32 = SecRandomCopyBytes(kSecRandomDefault,
                                                   kCCBlockSizeAES128,
                                                   dataBytesBaseAddress)
            
            guard status == 0 else {
                throw Error.generateRandomIVFailed
            }
            
        }
        
    }
    
}
