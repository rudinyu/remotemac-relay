import Cocoa

/// Native macOS front-end for the remote-desktop viewer. A small connection form
/// gathers relay/device/passphrase, then opens a window that renders the host's
/// screen and forwards mouse + keyboard input over the verified RemoteMacCore
/// transport.
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var connectWindow: NSWindow!
    private var viewerWindow: NSWindow?
    private var session: Session?

    private var hostField: NSTextField!
    private var portField: NSTextField!
    private var deviceField: NSTextField!
    private var pskField: NSSecureTextField!
    private var rememberBox: NSButton!
    private var statusLabel: NSTextField!
    private var connectButton: NSButton!

    private let defaults = UserDefaults.standard

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        buildConnectWindow()
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    // ── connection form ─────────────────────────────────────────────────────────

    private func buildConnectWindow() {
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 380, height: 262),
                         styleMask: [.titled, .closable, .miniaturizable],
                         backing: .buffered, defer: false)
        w.title = "RemoteMac Viewer"
        w.center()
        let content = NSView(frame: NSRect(x: 0, y: 0, width: 380, height: 262))
        w.contentView = content

        func label(_ text: String, _ y: CGFloat) -> NSTextField {
            let l = NSTextField(labelWithString: text)
            l.frame = NSRect(x: 20, y: y, width: 90, height: 20)
            l.alignment = .right
            content.addSubview(l); return l
        }
        func place<T: NSTextField>(_ f: T, _ y: CGFloat) -> T {
            f.frame = NSRect(x: 120, y: y, width: 240, height: 22)
            content.addSubview(f); return f
        }

        _ = label("Relay host:", 224); hostField = place(NSTextField(), 223)
        _ = label("Port:", 194);       portField = place(NSTextField(), 193)
        _ = label("Device ID:", 164);  deviceField = place(NSTextField(), 163)
        _ = label("Passphrase:", 134); pskField = place(NSSecureTextField(), 133)

        rememberBox = NSButton(checkboxWithTitle: "Remember passphrase (Keychain)", target: nil, action: nil)
        rememberBox.frame = NSRect(x: 120, y: 104, width: 250, height: 20)
        content.addSubview(rememberBox)

        connectButton = NSButton(title: "Connect", target: self, action: #selector(connectPressed))
        connectButton.frame = NSRect(x: 250, y: 60, width: 110, height: 32)
        connectButton.bezelStyle = .rounded
        connectButton.keyEquivalent = "\r"
        content.addSubview(connectButton)

        statusLabel = NSTextField(labelWithString: "")
        statusLabel.frame = NSRect(x: 20, y: 24, width: 340, height: 20)
        statusLabel.textColor = .secondaryLabelColor
        content.addSubview(statusLabel)

        // restore last-used connection details.
        hostField.stringValue = defaults.string(forKey: "relayHost") ?? ""
        portField.stringValue = defaults.string(forKey: "port") ?? "21100"
        deviceField.stringValue = defaults.string(forKey: "deviceId") ?? ""
        deviceField.target = self
        deviceField.action = #selector(deviceChanged)
        loadSavedPassphrase()

        connectWindow = w
        w.makeKeyAndOrderFront(nil)
    }

    @objc private func deviceChanged() { loadSavedPassphrase() }

    private func loadSavedPassphrase() {
        let device = deviceField.stringValue.trimmingCharacters(in: .whitespaces)
        if !device.isEmpty, let saved = Keychain.load(for: device) {
            pskField.stringValue = saved
            rememberBox.state = .on
        }
    }

    @objc private func connectPressed() {
        let host = hostField.stringValue.trimmingCharacters(in: .whitespaces)
        let device = deviceField.stringValue.trimmingCharacters(in: .whitespaces)
        let psk = pskField.stringValue
        guard let port = Int(portField.stringValue.trimmingCharacters(in: .whitespaces)), port > 0, port < 65536 else {
            setStatus("Enter a valid port.", error: true); return
        }
        guard !host.isEmpty, !device.isEmpty, !psk.isEmpty else {
            setStatus("Relay host, device id and passphrase are required.", error: true); return
        }

        defaults.set(host, forKey: "relayHost")
        defaults.set(String(port), forKey: "port")
        defaults.set(device, forKey: "deviceId")
        if rememberBox.state == .on { Keychain.save(passphrase: psk, for: device) }
        else { Keychain.delete(for: device) }

        setStatus("Connecting…", error: false)
        connectButton.isEnabled = false

        let s = Session()
        s.onDisconnect = { [weak self] reason in self?.sessionEnded(reason) }
        session = s
        openViewerWindow(title: "\(device) @ \(host)", session: s)
        s.start(relayHost: host, port: port, deviceId: device, passphrase: psk)
    }

    private func setStatus(_ text: String, error: Bool) {
        statusLabel.stringValue = text
        statusLabel.textColor = error ? .systemRed : .secondaryLabelColor
    }

    private func sessionEnded(_ reason: String?) {
        connectButton.isEnabled = true
        viewerWindow?.close(); viewerWindow = nil
        session = nil
        connectWindow.makeKeyAndOrderFront(nil)
        setStatus(reason.map { "Disconnected: \($0)" } ?? "Disconnected.", error: reason != nil)
    }

    // ── viewer window ────────────────────────────────────────────────────────────

    private func openViewerWindow(title: String, session: Session) {
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1024, height: 640),
                         styleMask: [.titled, .closable, .miniaturizable, .resizable],
                         backing: .buffered, defer: false)
        w.title = title
        w.center()
        w.delegate = self

        let view = RemoteView(frame: w.contentView!.bounds)
        view.autoresizingMask = [.width, .height]
        view.session = session
        w.contentView = view

        session.onFrame = { [weak view] jpeg, width, height in
            view?.update(jpeg: jpeg, width: width, height: height)
        }

        viewerWindow = w
        connectWindow.orderOut(nil)
        w.makeKeyAndOrderFront(nil)
        w.makeFirstResponder(view)
    }

    // ── menu (so ⌘Q etc. work) ──────────────────────────────────────────────────

    private func buildMenu() {
        let mainMenu = NSMenu()
        let appItem = NSMenuItem()
        mainMenu.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Quit RemoteMac Viewer", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        NSApp.mainMenu = mainMenu
    }
}

extension AppDelegate: NSWindowDelegate {
    func windowWillClose(_ notification: Notification) {
        guard let closing = notification.object as? NSWindow, closing === viewerWindow else { return }
        session?.stop()
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.regular)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
