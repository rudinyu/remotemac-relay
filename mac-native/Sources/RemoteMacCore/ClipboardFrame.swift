import Foundation

/// Text clipboard frame shared with remote_desktop.py: type, 32-bit byte count,
/// then UTF-8. Keep the same 1 MiB limit as the Python host.
public enum ClipboardFrame {
    public static let type: UInt8 = 0x06
    public static let maxBytes = 1024 * 1024

    public static func encode(_ text: String) -> [UInt8]? {
        let bytes = Array(text.utf8)
        guard !bytes.isEmpty, bytes.count <= maxBytes else { return nil }
        let n = UInt32(bytes.count)
        return [type, UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff),
                UInt8((n >> 8) & 0xff), UInt8(n & 0xff)] + bytes
    }

    public static func decode(_ frame: [UInt8]) -> String? {
        guard frame.count >= 5, frame[0] == type else { return nil }
        let n = Int(frame[1]) << 24 | Int(frame[2]) << 16 |
                Int(frame[3]) << 8 | Int(frame[4])
        guard n <= maxBytes, frame.count == n + 5 else { return nil }
        return String(bytes: frame[5...], encoding: .utf8)
    }
}
