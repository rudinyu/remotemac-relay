import XCTest
@testable import RemoteMacCore

final class CryptoTests: XCTestCase {
    func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
    func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }

    func testSHAKE256Vectors() {
        XCTAssertEqual(hex(SHAKE256.digest(bytes(""), 32)),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        XCTAssertEqual(hex(SHAKE256.digest(bytes("abc"), 32)),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739")
    }

    func testHMAC() {
        let key = (0..<32).map { UInt8($0) }
        XCTAssertEqual(hex(hmacSHA256(key: key, bytes("abc"))),
            "f0133729c4163dede81e21cd47839256da58171238c8a0d874397c73b14e1e47")
    }

    func testScryptMatchesPython() {
        let psk = bytes("correct horse battery staple")
        let salt = (0..<64).map { UInt8($0) }
        let master = Scrypt.derive(password: psk, salt: salt, n: 16384, r: 8, p: 1, dkLen: 32)
        XCTAssertEqual(hex(master),
            "a0a56744cb4bc90c24a0992f7a28868d29d0c790698e0ff838c9c2b467a34042")
    }
}

extension CryptoTests {
    func testXofCipherKeystreamMatchesPython() {
        let key = (0..<32).map { UInt8($0) }
        let c = XofCipher(key: key)
        // crypt(zeros) returns the keystream; consecutive calls bump the counter.
        XCTAssertEqual(hex(c.crypt([UInt8](repeating: 0, count: 16))), "caac6f487add099067cdebb9b27416ee")
        XCTAssertEqual(hex(c.crypt([UInt8](repeating: 0, count: 16))), "891b47647ca41af1c88d0b4c22aa9156")
    }
}
