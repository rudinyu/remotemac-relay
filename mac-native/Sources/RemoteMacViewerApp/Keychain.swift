import Foundation
import Security

/// Passphrase storage in the login Keychain. Secrets never enter process arguments.
enum Keychain {
    private static let service = "remotemac-relay-viewer"

    private static func query(for account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    @discardableResult
    static func save(passphrase: String, for account: String) -> Bool {
        let data = Data(passphrase.utf8)
        let status = SecItemUpdate(query(for: account) as CFDictionary,
                                   [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return true }
        guard status == errSecItemNotFound else { return false }
        var item = query(for: account)
        item[kSecValueData as String] = data
        return SecItemAdd(item as CFDictionary, nil) == errSecSuccess
    }

    static func load(for account: String) -> String? {
        var item = query(for: account)
        item[kSecReturnData as String] = true
        item[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(item as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func delete(for account: String) {
        SecItemDelete(query(for: account) as CFDictionary)
    }
}
