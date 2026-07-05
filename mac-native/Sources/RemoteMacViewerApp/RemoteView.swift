import Cocoa

/// Renders the received desktop frames (letterboxed, aspect-preserving) and
/// translates local mouse/keyboard events into host input, mirroring the
/// tkinter viewer in remote_desktop.py.
final class RemoteView: NSView {
    weak var session: Session?

    private var image: NSImage?
    private var frameSize: NSSize = .zero
    private var modsDown = Set<UInt16>()          // currently-held modifier keyCodes

    override var acceptsFirstResponder: Bool { true }
    override var isFlipped: Bool { false }         // AppKit default: origin bottom-left

    /// Called on the main thread with a decoded JPEG frame.
    func update(jpeg: Data, width: Int, height: Int) {
        if let img = NSImage(data: jpeg) {
            image = img
            frameSize = NSSize(width: max(1, width), height: max(1, height))
            needsDisplay = true
        }
    }

    // Displayed image rectangle inside the view (letterboxed).
    private func imageRect() -> NSRect {
        guard frameSize.width > 0, frameSize.height > 0, bounds.width > 0, bounds.height > 0
        else { return bounds }
        let scale = min(bounds.width / frameSize.width, bounds.height / frameSize.height)
        let dw = frameSize.width * scale, dh = frameSize.height * scale
        return NSRect(x: (bounds.width - dw) / 2, y: (bounds.height - dh) / 2, width: dw, height: dh)
    }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.black.setFill()
        bounds.fill()
        image?.draw(in: imageRect(), from: .zero, operation: .copy, fraction: 1.0)
    }

    // ── mouse ────────────────────────────────────────────────────────────────

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(rect: .zero,
                                       options: [.mouseMoved, .activeInKeyWindow, .inVisibleRect],
                                       owner: self, userInfo: nil))
    }

    // Normalise a window-space point to the host's 0…65535 coord space, with the
    // Y axis flipped to top-origin (AppKit views are bottom-origin here).
    private func norm(_ event: NSEvent) -> (UInt16, UInt16) {
        let p = convert(event.locationInWindow, from: nil)
        let r = imageRect()
        let w = r.width > 0 ? r.width : 1, h = r.height > 0 ? r.height : 1
        func clamp(_ v: CGFloat) -> UInt16 { UInt16(max(0, min(65535, (v * 65535).rounded()))) }
        return (clamp((p.x - r.minX) / w), clamp((r.maxY - p.y) / h))
    }

    override func mouseMoved(with e: NSEvent)   { let (x, y) = norm(e); session?.sendMouseMove(xn: x, yn: y) }
    override func mouseDragged(with e: NSEvent) { let (x, y) = norm(e); session?.sendMouseMove(xn: x, yn: y) }
    override func rightMouseDragged(with e: NSEvent) { mouseDragged(with: e) }
    override func otherMouseDragged(with e: NSEvent) { mouseDragged(with: e) }

    override func mouseDown(with e: NSEvent) {
        window?.makeFirstResponder(self)
        let (x, y) = norm(e); session?.sendMouseMove(xn: x, yn: y)
        session?.sendMouseButton(0, down: true)
    }
    override func mouseUp(with e: NSEvent)        { session?.sendMouseButton(0, down: false) }
    override func rightMouseDown(with e: NSEvent) { let (x, y) = norm(e); session?.sendMouseMove(xn: x, yn: y); session?.sendMouseButton(1, down: true) }
    override func rightMouseUp(with e: NSEvent)   { session?.sendMouseButton(1, down: false) }
    override func otherMouseDown(with e: NSEvent) {
        guard e.buttonNumber == 2 else { return }
        let (x, y) = norm(e); session?.sendMouseMove(xn: x, yn: y)
        session?.sendMouseButton(2, down: true)
    }
    override func otherMouseUp(with e: NSEvent)   { if e.buttonNumber == 2 { session?.sendMouseButton(2, down: false) } }

    override func scrollWheel(with e: NSEvent) {
        func clamp(_ v: Double) -> Int16 { Int16(max(-32768, min(32767, v.rounded()))) }
        let dx = clamp(Double(e.scrollingDeltaX))
        let dy = clamp(Double(e.scrollingDeltaY))
        if dx != 0 || dy != 0 { session?.sendScroll(dx: dx, dy: dy) }
    }

    // ── keyboard ───────────────────────────────────────────────────────────────

    // macOS virtual keycode → pynput key string (Key.<name>), matching _str_to_key.
    private static let specialKeys: [UInt16: String] = [
        36: "Key.enter", 76: "Key.enter", 51: "Key.backspace", 48: "Key.tab",
        53: "Key.esc", 117: "Key.delete", 115: "Key.home", 119: "Key.end",
        116: "Key.page_up", 121: "Key.page_down",
        126: "Key.up", 125: "Key.down", 123: "Key.left", 124: "Key.right",
        49: " ",
        122: "Key.f1", 120: "Key.f2", 99: "Key.f3", 118: "Key.f4", 96: "Key.f5",
        97: "Key.f6", 98: "Key.f7", 100: "Key.f8", 101: "Key.f9", 109: "Key.f10",
        103: "Key.f11", 111: "Key.f12",
    ]
    private static let modifierKeys: [UInt16: String] = [
        56: "Key.shift_l", 60: "Key.shift_r", 59: "Key.ctrl_l", 62: "Key.ctrl_r",
        58: "Key.alt_l", 61: "Key.alt_r", 55: "Key.cmd", 54: "Key.cmd_r",
        57: "Key.caps_lock",
    ]

    private func keyString(for e: NSEvent) -> String? {
        if let s = RemoteView.specialKeys[e.keyCode] { return s }
        guard let ch = e.charactersIgnoringModifiers ?? e.characters, ch.count == 1,
              let scalar = ch.unicodeScalars.first, scalar.value >= 0x20, scalar.value != 0x7f
        else { return nil }
        return ch
    }

    override func keyDown(with e: NSEvent) {
        if let s = keyString(for: e) { session?.sendKey(s, down: true) }
        // swallow — no super call, so no system beep for unhandled keys
    }
    override func keyUp(with e: NSEvent) {
        if let s = keyString(for: e) { session?.sendKey(s, down: false) }
    }

    override func flagsChanged(with e: NSEvent) {
        guard let s = RemoteView.modifierKeys[e.keyCode] else { return }
        let down = !modsDown.contains(e.keyCode)
        if down { modsDown.insert(e.keyCode) } else { modsDown.remove(e.keyCode) }
        session?.sendKey(s, down: down)
    }

    // Losing focus mid-hold (⌘-Tab away) would otherwise leave modifiers "stuck"
    // on the host and desync our parity — release everything we think is held.
    override func resignFirstResponder() -> Bool {
        for code in modsDown {
            if let s = RemoteView.modifierKeys[code] { session?.sendKey(s, down: false) }
        }
        modsDown.removeAll()
        return super.resignFirstResponder()
    }
}
