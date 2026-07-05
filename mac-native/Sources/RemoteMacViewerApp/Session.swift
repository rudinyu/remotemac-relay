import Foundation
import RemoteMacCore

/// A live viewer session: owns the relay-bridged `SecureChannel`, pumps incoming
/// `MSG_FRAME`s to `onFrame`, and encodes viewer→host input events. All wire
/// formats mirror remote_desktop.py exactly (see the MSG_* constants there).
final class Session {
    // remote-desktop protocol message types (host↔viewer).
    private static let MSG_FRAME: UInt8        = 0x01
    private static let MSG_MOUSE_MOVE: UInt8   = 0x02
    private static let MSG_MOUSE_BTN: UInt8    = 0x03
    private static let MSG_MOUSE_SCROLL: UInt8 = 0x04
    private static let MSG_KEY: UInt8          = 0x05
    private static let MSG_PING: UInt8         = 0x07
    private static let MSG_PONG: UInt8         = 0x08

    /// Delivered on the main thread: (jpeg bytes, width, height).
    var onFrame: ((Data, Int, Int) -> Void)?
    /// Delivered on the main thread once, when the session ends (nil = clean).
    var onDisconnect: ((String?) -> Void)?

    private var channel: SecureChannel?
    private let ioQueue = DispatchQueue(label: "remotemac.session.send")   // serialises all sends
    private var running = false
    private var pingTimer: DispatchSourceTimer?
    private let stateLock = NSLock()
    private var finished = false

    /// Connect through the relay and authenticate, off the main thread. On success
    /// the receive loop starts; on failure `onDisconnect` fires with the message.
    func start(relayHost: String, port: Int, deviceId: String, passphrase: String) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            do {
                let sock = try RelayClient.connectViaRelay(host: relayHost, port: port, deviceId: deviceId)
                let ch = try RelayClient.clientAuth(sock: sock, psk: Array(passphrase.utf8))
                self.channel = ch
                self.running = true
                self.startPing()
                self.recvLoop(ch)
            } catch {
                self.finish("\(error)")
            }
        }
    }

    /// User-initiated clean stop (e.g. the viewer window was closed). Fires
    /// `onDisconnect(nil)` exactly once, like any other teardown.
    func stop() { finish(nil) }

    /// Single idempotent teardown path — reached from a clean stop, an I/O error,
    /// or a failed connect. Guaranteed to deliver `onDisconnect` once.
    private func finish(_ reason: String?) {
        stateLock.lock()
        if finished { stateLock.unlock(); return }
        finished = true
        running = false
        stateLock.unlock()
        pingTimer?.cancel(); pingTimer = nil
        channel?.close()
        DispatchQueue.main.async { [weak self] in self?.onDisconnect?(reason); self?.onDisconnect = nil }
    }

    private func recvLoop(_ ch: SecureChannel) {
        while running {
            let frame: [UInt8]
            do { frame = try ch.recv() } catch {
                if running { finish("\(error)") }
                return
            }
            guard let type = frame.first else { continue }
            switch type {
            case Session.MSG_FRAME where frame.count >= 5:
                let w = Int(frame[1]) << 8 | Int(frame[2])
                let h = Int(frame[3]) << 8 | Int(frame[4])
                let jpeg = Data(frame[5...])
                DispatchQueue.main.async { [weak self] in self?.onFrame?(jpeg, w, h) }
            case Session.MSG_PING:
                send([Session.MSG_PONG])
            default:
                break   // MSG_PONG / MSG_CLIP — ignored for now
            }
        }
    }

    private func startPing() {
        let t = DispatchSource.makeTimerSource(queue: ioQueue)
        t.schedule(deadline: .now() + 30, repeating: 30)
        t.setEventHandler { [weak self] in self?.send([Session.MSG_PING]) }
        pingTimer = t
        t.resume()
    }

    // ── outgoing frames ────────────────────────────────────────────────────────

    private func send(_ bytes: [UInt8]) {
        ioQueue.async { [weak self] in
            guard let self = self, self.running, let ch = self.channel else { return }
            do { try ch.send(bytes) } catch { self.finish("send: \(error)") }
        }
    }

    private func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }
    private func be16(_ v: Int16) -> [UInt8] { be16(UInt16(bitPattern: v)) }

    func sendMouseMove(xn: UInt16, yn: UInt16) {
        send([Session.MSG_MOUSE_MOVE] + be16(xn) + be16(yn))
    }
    /// btn: 0=left 1=right 2=middle.
    func sendMouseButton(_ btn: UInt8, down: Bool) {
        send([Session.MSG_MOUSE_BTN, btn, down ? 1 : 0])
    }
    func sendScroll(dx: Int16, dy: Int16) {
        send([Session.MSG_MOUSE_SCROLL] + be16(dx) + be16(dy))
    }
    func sendKey(_ keyStr: String, down: Bool) {
        send([Session.MSG_KEY, down ? 1 : 0] + Array(keyStr.utf8))
    }
}
