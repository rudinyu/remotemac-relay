import Foundation

public enum AuthError: Error, CustomStringConvertible {
    case relay(String), auth(String)
    public var description: String {
        switch self {
        case .relay(let m): return "relay: \(m)"
        case .auth(let m): return "auth: \(m)"
        }
    }
}

/// Client side of the relay + auth handshake, ported from remote_desktop.py.
public enum RelayClient {
    // scrypt parameters (must match the host).
    static let scryptN = 16384, scryptR = 8, scryptP = 1

    private static func expand(_ master: [UInt8], _ label: String) -> [UInt8] {
        hmacSHA256(key: master, Array(label.utf8) + [0x01])
    }

    /// Connect to the relay and pair with the host for `deviceId` (client role).
    /// Returns a raw socket bridged to the host, ready for `clientAuth`.
    public static func connectViaRelay(host: String, port: Int, deviceId: String) throws -> RMSocket {
        let sock = try RMSocket.connect(host: host, port: port)
        var rid = Array(deviceId.utf8.prefix(8))
        while rid.count < 8 { rid.append(0) }
        try sock.writeAll(Array("C".utf8) + rid)
        let resp = try sock.readExactly(1)
        switch resp[0] {
        case UInt8(ascii: "P"): return sock
        case UInt8(ascii: "N"): sock.close(); throw AuthError.relay("no host for that device id")
        case UInt8(ascii: "D"): sock.close(); throw AuthError.relay("host slot occupied by another IP")
        default: sock.close(); throw AuthError.relay("unexpected response \(resp[0])")
        }
    }

    /// Run the mutual scrypt-auth handshake as the client over an already-bridged
    /// socket, returning the encrypted channel on success.
    public static func clientAuth(sock: RMSocket, psk: [UInt8]) throws -> SecureChannel {
        // client: read the host nonce first, then send ours.
        let nonceH = try sock.readExactly(32)
        var rng = SystemRandomNumberGenerator()          // cryptographically secure on Apple platforms
        let nonceC = (0..<32).map { _ in UInt8.random(in: 0...255, using: &rng) }
        try sock.writeAll(nonceC)

        let salt = nonceH + nonceC
        let master = Scrypt.derive(password: psk, salt: salt, n: scryptN, r: scryptR, p: scryptP, dkLen: 32)
        let encH2C = expand(master, "enc-h2c")
        let encC2H = expand(master, "enc-c2h")
        let macH2C = expand(master, "mac-h2c")
        let macC2H = expand(master, "mac-c2h")
        let authK  = expand(master, "auth")

        let myToken = hmacSHA256(key: authK, Array("client".utf8) + nonceH + nonceC)
        let expected = hmacSHA256(key: authK, Array("host".utf8) + nonceH + nonceC)

        // client: read the host's token first, then send ours.
        let peerToken = try sock.readExactly(32)
        try sock.writeAll(myToken)
        guard constantTimeEqual(peerToken, expected) else {
            throw AuthError.auth("peer does not know the passphrase")
        }
        return SecureChannel(sock: sock, enc: encC2H, dec: encH2C, macSend: macC2H, macRecv: macH2C)
    }
}
