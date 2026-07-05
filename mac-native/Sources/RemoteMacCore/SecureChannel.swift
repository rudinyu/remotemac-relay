import Foundation

/// SHAKE-256 XOF counter-mode stream cipher — one Keccak call per frame.
/// Keystream = SHAKE256(key ‖ be64(counter)); ciphertext = plaintext XOR keystream.
final class XofCipher {
    private let key: [UInt8]
    private var counter: UInt64 = 0
    init(key: [UInt8]) { self.key = key }

    func crypt(_ data: [UInt8]) -> [UInt8] {
        if data.isEmpty { return [] }
        let ks = SHAKE256.digest(key + beBytes(counter), data.count)
        counter += 1
        var out = [UInt8](repeating: 0, count: data.count)
        for i in 0..<data.count { out[i] = data[i] ^ ks[i] }
        return out
    }
}

/// Framed, encrypted, integrity-checked duplex channel — the Swift port of
/// remote_desktop.py's SecureChannel. Frame = be32(len) ‖ 32B HMAC ‖ ciphertext,
/// where HMAC = HMAC-SHA256(macKey, be64(seq) ‖ ciphertext) and seq is a per-
/// direction monotone counter.
public final class SecureChannel {
    private let sock: RMSocket
    private let enc: XofCipher
    private let dec: XofCipher
    private let macSend: [UInt8]
    private let macRecv: [UInt8]
    private var sseq: UInt64 = 0
    private var rseq: UInt64 = 0
    private let maxFrame = 4 * 1024 * 1024
    private let sendLock = NSLock()          // send() may be called from multiple threads

    init(sock: RMSocket, enc: [UInt8], dec: [UInt8], macSend: [UInt8], macRecv: [UInt8]) {
        self.sock = sock
        self.enc = XofCipher(key: enc)
        self.dec = XofCipher(key: dec)
        self.macSend = macSend
        self.macRecv = macRecv
    }

    public func send(_ plaintext: [UInt8]) throws {
        sendLock.lock()
        defer { sendLock.unlock() }
        let ct = enc.crypt(plaintext)
        let mac = hmacSHA256(key: macSend, beBytes(sseq) + ct)
        sseq += 1
        try sock.writeAll(beBytes(UInt32(ct.count)) + mac + ct)
    }

    public func recv() throws -> [UInt8] {
        let lenBytes = try sock.readExactly(4)
        let length = Int(UInt32(lenBytes[0]) << 24 | UInt32(lenBytes[1]) << 16
                         | UInt32(lenBytes[2]) << 8 | UInt32(lenBytes[3]))
        if length > maxFrame { throw SocketError.io("frame too large: \(length)") }
        let mac = try sock.readExactly(32)
        let ct = try sock.readExactly(length)
        let expected = hmacSHA256(key: macRecv, beBytes(rseq) + ct)
        guard constantTimeEqual(mac, expected) else {
            throw SocketError.io("MAC verification failed — wrong passphrase or tampered frame")
        }
        rseq += 1
        return dec.crypt(ct)
    }

    public func close() { sock.close() }
}
