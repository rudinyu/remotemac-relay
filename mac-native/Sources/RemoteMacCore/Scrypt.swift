import Foundation

/// scrypt(N, r, p) — matches Python's `hashlib.scrypt(pw, salt=..., n, r, p, dklen)`
/// (and the `cryptography` Scrypt KDF). Used for the SecureChannel auth handshake.
public enum Scrypt {
    private static func rotl(_ v: UInt32, _ n: UInt32) -> UInt32 {
        (v << n) | (v >> (32 - n))
    }

    // Salsa20/8 core on 16 little-endian 32-bit words.
    private static func salsa20_8(_ input: [UInt32]) -> [UInt32] {
        var x = input
        for _ in 0..<4 {
            x[4]  ^= rotl(x[0]  &+ x[12], 7);  x[8]  ^= rotl(x[4]  &+ x[0],  9)
            x[12] ^= rotl(x[8]  &+ x[4], 13);  x[0]  ^= rotl(x[12] &+ x[8], 18)
            x[9]  ^= rotl(x[5]  &+ x[1],  7);  x[13] ^= rotl(x[9]  &+ x[5],  9)
            x[1]  ^= rotl(x[13] &+ x[9], 13);  x[5]  ^= rotl(x[1]  &+ x[13],18)
            x[14] ^= rotl(x[10] &+ x[6],  7);  x[2]  ^= rotl(x[14] &+ x[10], 9)
            x[6]  ^= rotl(x[2]  &+ x[14],13);  x[10] ^= rotl(x[6]  &+ x[2], 18)
            x[3]  ^= rotl(x[15] &+ x[11], 7);  x[7]  ^= rotl(x[3]  &+ x[15], 9)
            x[11] ^= rotl(x[7]  &+ x[3], 13);  x[15] ^= rotl(x[11] &+ x[7], 18)
            x[1]  ^= rotl(x[0]  &+ x[3],  7);  x[2]  ^= rotl(x[1]  &+ x[0],  9)
            x[3]  ^= rotl(x[2]  &+ x[1], 13);  x[0]  ^= rotl(x[3]  &+ x[2], 18)
            x[6]  ^= rotl(x[5]  &+ x[4],  7);  x[7]  ^= rotl(x[6]  &+ x[5],  9)
            x[4]  ^= rotl(x[7]  &+ x[6], 13);  x[5]  ^= rotl(x[4]  &+ x[7], 18)
            x[11] ^= rotl(x[10] &+ x[9],  7);  x[8]  ^= rotl(x[11] &+ x[10], 9)
            x[9]  ^= rotl(x[8]  &+ x[11],13);  x[10] ^= rotl(x[9]  &+ x[8], 18)
            x[12] ^= rotl(x[15] &+ x[14], 7);  x[13] ^= rotl(x[12] &+ x[15], 9)
            x[14] ^= rotl(x[13] &+ x[12],13);  x[15] ^= rotl(x[14] &+ x[13],18)
        }
        var out = input
        for i in 0..<16 { out[i] = input[i] &+ x[i] }
        return out
    }

    // BlockMix over 2r 64-byte blocks (32r words).
    private static func blockMix(_ b: [UInt32], _ r: Int) -> [UInt32] {
        var x = Array(b[(2*r - 1)*16 ..< 2*r*16])
        var y = [UInt32](repeating: 0, count: 32*r)
        for i in 0..<(2*r) {
            var t = [UInt32](repeating: 0, count: 16)
            for j in 0..<16 { t[j] = x[j] ^ b[i*16 + j] }
            x = salsa20_8(t)
            let dest = (i % 2 == 0) ? (i / 2) : (r + i / 2)
            for j in 0..<16 { y[dest*16 + j] = x[j] }
        }
        return y
    }

    private static func roMix(_ block: [UInt32], _ n: Int, _ r: Int) -> [UInt32] {
        var x = block
        var v = [[UInt32]](); v.reserveCapacity(n)
        for _ in 0..<n { v.append(x); x = blockMix(x, r) }
        for _ in 0..<n {
            let j = Int(x[(2*r - 1)*16]) % n     // Integerify: first word of the last block, mod N
            var t = [UInt32](repeating: 0, count: 32*r)
            for k in 0..<32*r { t[k] = x[k] ^ v[j][k] }
            x = blockMix(t, r)
        }
        return x
    }

    // PBKDF2-HMAC-SHA256 with iteration count 1 (all scrypt needs).
    private static func pbkdf2c1(_ password: [UInt8], _ salt: [UInt8], _ dkLen: Int) -> [UInt8] {
        var out = [UInt8](); out.reserveCapacity(dkLen)
        var i: UInt32 = 1
        while out.count < dkLen {
            out.append(contentsOf: hmacSHA256(key: password, salt + beBytes(i)))
            i += 1
        }
        return Array(out.prefix(dkLen))
    }

    private static func bytesToWordsLE(_ b: [UInt8]) -> [UInt32] {
        var w = [UInt32](repeating: 0, count: b.count / 4)
        for i in 0..<w.count {
            w[i] = UInt32(b[i*4]) | UInt32(b[i*4+1]) << 8 | UInt32(b[i*4+2]) << 16 | UInt32(b[i*4+3]) << 24
        }
        return w
    }

    private static func wordsToBytesLE(_ w: [UInt32]) -> [UInt8] {
        var b = [UInt8](); b.reserveCapacity(w.count * 4)
        for v in w { b.append(UInt8(v & 0xff)); b.append(UInt8(v >> 8 & 0xff)); b.append(UInt8(v >> 16 & 0xff)); b.append(UInt8(v >> 24 & 0xff)) }
        return b
    }

    public static func derive(password: [UInt8], salt: [UInt8], n: Int, r: Int, p: Int, dkLen: Int) -> [UInt8] {
        var words = bytesToWordsLE(pbkdf2c1(password, salt, p * 128 * r))
        let blockWords = 32 * r
        for i in 0..<p {
            let start = i * blockWords
            let mixed = roMix(Array(words[start..<start+blockWords]), n, r)
            for k in 0..<blockWords { words[start + k] = mixed[k] }
        }
        return pbkdf2c1(password, wordsToBytesLE(words), dkLen)
    }
}
