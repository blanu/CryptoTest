import XCTest
@testable import CryptoTest

import CryptoKit

final class CryptoTestTests: XCTestCase
{
    func testPublicKeySizes()
    {
        let privateSigningKey = P256.Signing.PrivateKey()
        let publicSigningKey = privateSigningKey.publicKey
        
        XCTAssertEqual(publicSigningKey.rawRepresentation.count, 64)
        
        guard let compact = publicSigningKey.compactRepresentation else
        {
            XCTFail()
            return
        }
        XCTAssertEqual(compact.count, 32)
        
        XCTAssertEqual(publicSigningKey.x963Representation.count, 65)
        
        let privateEncryptionKey = P256.KeyAgreement.PrivateKey()
        let publicEncryptionKey = privateEncryptionKey.publicKey

        XCTAssertEqual(publicEncryptionKey.rawRepresentation.count, 64)
        
        guard let compact2 = publicEncryptionKey.compactRepresentation else
        {
            XCTFail()
            return
        }
        XCTAssertEqual(compact2.count, 32)
        
        XCTAssertEqual(publicEncryptionKey.x963Representation.count, 65)
    }
    
    func testEncryptDecryptSignVerify()
    {
        let data = Data(repeating: 0xA0, count: 1024)
                
        guard let (privateEncryptionKeyB, privateEphemeralKey, privateSigningKeyA) = newTestKeys() else
        {
            XCTFail()
            return
        }
        
        let sender = Sender(senderPrivateEphemeralEncryptionKey: privateEphemeralKey, senderPrivateSigningKey: privateSigningKeyA, receiverPublicEncryptionKey: privateEncryptionKeyB.publicKey)

        guard let (encrypted, signature) = sender.encryptAndSign(data: data) else
        {
            XCTFail()
            return
        }

        guard let receiver = try? Receiver(publicEncryptionKeyData: privateEphemeralKey.publicKey.rawRepresentation, publicSigningKeyData: privateSigningKeyA.publicKey.rawRepresentation, privateEncryption: privateEncryptionKeyB) else
        {
            XCTFail()
            return
        }
                
        guard let decrypted = receiver.verifyAndDecrypt(encrypted: encrypted, signature: signature) else
        {
            XCTFail()
            return
        }
                
        XCTAssertEqual(decrypted, data)
    }
    
    func testEncryptionOverhead()
    {
        let data = Data(repeating: 0xA0, count: 1024)
                
        guard let (privateEncryptionKeyB, privateEphemeralKey, privateSigningKeyA) = newTestKeys() else
        {
            XCTFail()
            return
        }
        
        let sender = Sender(senderPrivateEphemeralEncryptionKey: privateEphemeralKey, senderPrivateSigningKey: privateSigningKeyA, receiverPublicEncryptionKey: privateEncryptionKeyB.publicKey)

        guard let encrypted = sender.encrypt(data: data) else
        {
            XCTFail()
            return
        }
        
        XCTAssertEqual(data.count + 28, encrypted.count)
    }
    
    struct Sender
    {
        let senderPrivateEphemeralEncryptionKey: PrivateEncryptionKey
        let senderPrivateSigningKey: PrivateSigningKey
        let receiverPublicEncryptionKey: P256.KeyAgreement.PublicKey
        
        func encrypt(data: Data) -> Data?
        {
            guard let sharedSecret = try? senderPrivateEphemeralEncryptionKey.sharedSecretFromKeyAgreement(with: receiverPublicEncryptionKey) else
            {
                return nil
            }

            let sharedInfo = senderPrivateEphemeralEncryptionKey.publicKey.rawRepresentation + receiverPublicEncryptionKey.rawRepresentation + senderPrivateSigningKey.publicKey.rawRepresentation

            let symmetricKey = sharedSecret.x963DerivedSymmetricKey(
                using: SHA256.self,
                sharedInfo: sharedInfo,
                outputByteCount: 32
            )

            guard let encrypted = try? ChaChaPoly.seal(data, using: symmetricKey).combined else {
                return nil
            }

            return encrypted
        }
        
        func sign(data: Data) -> P256.Signing.ECDSASignature?
        {
            let signableData = data + senderPrivateEphemeralEncryptionKey.publicKey.rawRepresentation + receiverPublicEncryptionKey.rawRepresentation
            
            guard let signature = try? senderPrivateSigningKey.signature(for: signableData) else
            {
                return nil
            }

            return signature
        }
        
        func encryptAndSign(data: Data) -> (Data, Data)?
        {
            guard let encrypted = encrypt(data: data) else
            {
                return nil
            }
            
            guard let signature = sign(data: encrypted) else
            {
                return nil
            }
            
            return (encrypted, signature.rawRepresentation)
        }
    }
    
    struct Receiver
    {
        let senderPublicEphemeralEncryptionKey: P256.KeyAgreement.PublicKey
        let senderPublicSigningKey: P256.Signing.PublicKey
        let receiverPrivateEncryptionKey: PrivateEncryptionKey
        
        init(publicEncryptionKeyData: Data, publicSigningKeyData: Data, privateEncryption: PrivateEncryptionKey) throws
        {
            self.senderPublicEphemeralEncryptionKey = try P256.KeyAgreement.PublicKey(rawRepresentation: publicEncryptionKeyData)
            self.senderPublicSigningKey = try P256.Signing.PublicKey(rawRepresentation: publicSigningKeyData)
            self.receiverPrivateEncryptionKey = privateEncryption
        }
        
        func verify(data: Data, signature: Data) -> Bool
        {
            let verifiableData = data + senderPublicEphemeralEncryptionKey.rawRepresentation + receiverPrivateEncryptionKey.publicKey.rawRepresentation
            
            guard let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else
            {
                return false
            }
            
            return senderPublicSigningKey.isValidSignature(sig, for: verifiableData)
        }
        
        func decrypt(encrypted: Data) -> Data?
        {
            guard let secret = try? receiverPrivateEncryptionKey.sharedSecretFromKeyAgreement(with: senderPublicEphemeralEncryptionKey) else
            {
                return nil
            }
            
            let sharedDecryptionData = senderPublicEphemeralEncryptionKey.rawRepresentation + receiverPrivateEncryptionKey.publicKey.rawRepresentation + senderPublicSigningKey.rawRepresentation
            
            let symmetricDecryptionKey = secret.x963DerivedSymmetricKey(
                using: SHA256.self,
                sharedInfo: sharedDecryptionData,
                outputByteCount: 32)
            
            guard let sealedBox = try? ChaChaPoly.SealedBox(combined: encrypted) else
            {
                return nil
            }
            
            guard let decrypted = try? ChaChaPoly.open(sealedBox, using: symmetricDecryptionKey) else
            {
                return nil
            }
            
            return decrypted
        }
        
        func verifyAndDecrypt(encrypted: Data, signature: Data) -> Data?
        {
            guard verify(data: encrypted, signature: signature) else
            {
                return nil
            }
            
            return decrypt(encrypted: encrypted)
        }
    }
    
    func newTestKeys() -> (PrivateEncryptionKey, PrivateEncryptionKey, PrivateSigningKey)?
    {
        guard let privateEncryptionKey = NewPrivateEncryptionKey() else
        {
            return nil
        }
        
        guard privateEncryptionKey.publicKey.compactRepresentation != nil else
        {
            return nil
        }

        guard let privateEphemeralEncryptionKey = NewPrivateEncryptionKey() else
        {
            return nil
        }
        
        guard privateEphemeralEncryptionKey.publicKey.compactRepresentation != nil else
        {
            return nil
        }
        
        guard let privateSigningKey = NewPrivateSigningKey() else
        {
            return nil
        }
        
        guard privateSigningKey.publicKey.compactRepresentation != nil else
        {
            return nil
        }
        
        return (privateEncryptionKey, privateEphemeralEncryptionKey, privateSigningKey)
    }
    
    enum PrivateEncryptionKey
    {
        case enclave(SecureEnclave.P256.KeyAgreement.PrivateKey)
        case noenclave(P256.KeyAgreement.PrivateKey)
        
        var publicKey: P256.KeyAgreement.PublicKey
        {
            get
            {
                switch(self)
                {
                    case .enclave(let privateKey):
                        return privateKey.publicKey
                    case .noenclave(let privateKey):
                        return privateKey.publicKey
                }
            }
        }
        
        func sharedSecretFromKeyAgreement(with publicEncryptionKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret
        {
            switch(self)
            {
                case .enclave(let privateKey):
                    return try privateKey.sharedSecretFromKeyAgreement(with: publicEncryptionKey)
                case .noenclave(let privateKey):
                    return try privateKey.sharedSecretFromKeyAgreement(with: publicEncryptionKey)
            }
        }
    }
    
    enum PrivateSigningKey
    {
        case enclave(SecureEnclave.P256.Signing.PrivateKey)
        case noenclave(P256.Signing.PrivateKey)
        
        var publicKey: P256.Signing.PublicKey
        {
            get
            {
                switch(self)
                {
                    case .enclave(let privateKey):
                        return privateKey.publicKey
                    case .noenclave(let privateKey):
                        return privateKey.publicKey
                }
            }
        }
        
        func signature(for signableData: Data) throws -> P256.Signing.ECDSASignature
        {
            switch(self)
            {
                case .enclave(let privateKey):
                    return try privateKey.signature(for: signableData)
                case .noenclave(let privateKey):
                    return try privateKey.signature(for: signableData)
            }
        }
    }

    func NewPrivateEncryptionKey() -> PrivateEncryptionKey?
    {
        if SecureEnclave.isAvailable
        {
            guard let privateEncryptionKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey() else
            {
                return nil
            }
            
            return .enclave(privateEncryptionKey)
        }
        else
        {
            return .noenclave(P256.KeyAgreement.PrivateKey())
        }
    }
    
    func NewPrivateSigningKey() -> PrivateSigningKey?
    {
        if SecureEnclave.isAvailable
        {
            guard let privateSigningKey = try? SecureEnclave.P256.Signing.PrivateKey() else
            {
                return nil
            }
            
            return .enclave(privateSigningKey)
        }
        else
        {
            return .noenclave(P256.Signing.PrivateKey())
        }
    }
}
