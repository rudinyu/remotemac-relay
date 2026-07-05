import Foundation
import Darwin

public enum SocketError: Error { case connectFailed(String), closed, io(String) }

/// Minimal blocking TCP client socket (connect + read/write exactly N bytes).
public final class RMSocket {
    private let fd: Int32

    private init(fd: Int32) { self.fd = fd }

    public static func connect(host: String, port: Int) throws -> RMSocket {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let info = res else {
            throw SocketError.connectFailed("cannot resolve \(host):\(port)")
        }
        defer { freeaddrinfo(res) }
        var ai: UnsafeMutablePointer<addrinfo>? = info
        while let cur = ai {
            let s = Darwin.socket(cur.pointee.ai_family, cur.pointee.ai_socktype, cur.pointee.ai_protocol)
            if s >= 0 {
                if Darwin.connect(s, cur.pointee.ai_addr, cur.pointee.ai_addrlen) == 0 {
                    return RMSocket(fd: s)
                }
                Darwin.close(s)
            }
            ai = cur.pointee.ai_next
        }
        throw SocketError.connectFailed("could not connect to \(host):\(port)")
    }

    public func writeAll(_ data: [UInt8]) throws {
        var sent = 0
        try data.withUnsafeBytes { raw in
            let base = raw.baseAddress!
            while sent < data.count {
                let n = write(fd, base + sent, data.count - sent)
                if n <= 0 { throw SocketError.io("write failed") }
                sent += n
            }
        }
    }

    public func readExactly(_ n: Int) throws -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: n)
        var got = 0
        try buf.withUnsafeMutableBytes { raw in
            let base = raw.baseAddress!
            while got < n {
                let r = read(fd, base + got, n - got)
                if r == 0 { throw SocketError.closed }
                if r < 0 { throw SocketError.io("read failed") }
                got += r
            }
        }
        return buf
    }

    public func close() { _ = Darwin.close(fd) }
}
