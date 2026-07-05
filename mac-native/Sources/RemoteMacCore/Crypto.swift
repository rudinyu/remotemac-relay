import Foundation
import CryptoKit

/// HMAC-SHA256 — matches Python's `hmac.new(key, msg, sha256).digest()`.
public func hmacSHA256(key: [UInt8], _ message: [UInt8]) -> [UInt8] {
    let mac = HMAC<SHA256>.authenticationCode(for: Data(message), using: SymmetricKey(data: Data(key)))
    return Array(mac)
}

/// Constant-time compare (matches `hmac.compare_digest`).
public func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count { diff |= a[i] ^ b[i] }
    return diff == 0
}

func beBytes(_ v: UInt32) -> [UInt8] {
    [UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)]
}

func beBytes(_ v: UInt64) -> [UInt8] {
    (0..<8).reversed().map { UInt8((v >> UInt64(8 * $0)) & 0xff) }
}
