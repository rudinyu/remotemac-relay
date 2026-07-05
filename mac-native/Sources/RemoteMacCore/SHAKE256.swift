import Foundation

/// SHAKE-256 extendable-output function (Keccak-f[1600], rate 1088 bits).
/// Matches Python's `hashlib.shake_256(x).digest(n)`.
public enum SHAKE256 {
    private static let roundConstants: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    // rho rotation offsets, indexed r[x + 5*y]
    private static let rho: [Int] = [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14,
    ]

    private static func rotl(_ v: UInt64, _ n: Int) -> UInt64 {
        n == 0 ? v : (v << UInt64(n)) | (v >> UInt64(64 - n))
    }

    private static func keccakF(_ a: inout [UInt64]) {
        for round in 0..<24 {
            // θ
            var c = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 { c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20] }
            var d = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 { d[x] = c[(x+4)%5] ^ rotl(c[(x+1)%5], 1) }
            for x in 0..<5 { for y in 0..<5 { a[x + 5*y] ^= d[x] } }
            // ρ and π
            var b = [UInt64](repeating: 0, count: 25)
            for x in 0..<5 { for y in 0..<5 {
                b[y + 5*((2*x + 3*y) % 5)] = rotl(a[x + 5*y], rho[x + 5*y])
            } }
            // χ
            for x in 0..<5 { for y in 0..<5 {
                a[x + 5*y] = b[x + 5*y] ^ ((~b[(x+1)%5 + 5*y]) & b[(x+2)%5 + 5*y])
            } }
            // ι
            a[0] ^= roundConstants[round]
        }
    }

    private static func absorbBlock(_ state: inout [UInt64], _ block: ArraySlice<UInt8>, _ rate: Int) {
        let base = block.startIndex
        for i in 0..<(rate / 8) {
            var lane: UInt64 = 0
            for j in 0..<8 { lane |= UInt64(block[base + i*8 + j]) << (8 * j) }
            state[i] ^= lane
        }
    }

    public static func digest(_ input: [UInt8], _ outputLength: Int) -> [UInt8] {
        let rate = 136            // 1088 bits
        var state = [UInt64](repeating: 0, count: 25)

        var offset = 0
        while offset + rate <= input.count {
            absorbBlock(&state, input[offset..<offset+rate], rate)
            keccakF(&state)
            offset += rate
        }
        // final block: remaining bytes + SHAKE domain (0x1F) + pad10*1 (0x80 on last byte)
        var last = Array(input[offset...])
        last.append(0x1F)
        while last.count < rate { last.append(0) }
        last[rate - 1] |= 0x80
        absorbBlock(&state, last[0..<rate], rate)
        keccakF(&state)

        var out = [UInt8]()
        out.reserveCapacity(outputLength)
        while out.count < outputLength {
            for i in 0..<(rate / 8) {
                var lane = state[i]
                for _ in 0..<8 {
                    if out.count >= outputLength { break }
                    out.append(UInt8(lane & 0xff))
                    lane >>= 8
                }
                if out.count >= outputLength { break }
            }
            if out.count < outputLength { keccakF(&state) }
        }
        return out
    }
}
