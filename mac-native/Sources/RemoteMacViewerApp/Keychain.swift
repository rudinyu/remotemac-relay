import Foundation

/// Minimal passphrase storage in the login keychain via the `security` CLI.
/// One generic-password item per device id, under a fixed service name.
enum Keychain {
    private static let service = "remotemac-relay-viewer"

    @discardableResult
    private static func run(_ args: [String], input: String? = nil) -> (Int32, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = args
        let out = Pipe(); p.standardOutput = out; p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return (-1, "") }
        p.waitUntilExit()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    static func save(passphrase: String, for account: String) {
        // -U updates in place if the item already exists.
        run(["add-generic-password", "-U", "-a", account, "-s", service, "-w", passphrase])
    }

    static func load(for account: String) -> String? {
        let (status, out) = run(["find-generic-password", "-a", account, "-s", service, "-w"])
        guard status == 0 else { return nil }
        let trimmed = out.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    static func delete(for account: String) {
        run(["delete-generic-password", "-a", account, "-s", service])
    }
}
