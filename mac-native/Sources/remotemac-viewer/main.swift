import Foundation
import RemoteMacCore

func die(_ msg: String) -> Never {
    FileHandle.standardError.write(Data((msg + "\n").utf8)); exit(1)
}

let args = CommandLine.arguments
guard args.count >= 2 else {
    print("usage:")
    print("  remotemac-viewer authtest <host> <port> <passphrase>            # raw auth + one frame each way")
    print("  remotemac-viewer connect  <relay-host> <port> <device> <psk>    # via relay, print incoming frames")
    exit(1)
}

switch args[1] {
case "authtest":
    guard args.count == 5, let port = Int(args[3]) else { die("usage: authtest <host> <port> <passphrase>") }
    do {
        let sock = try RMSocket.connect(host: args[2], port: port)
        let ch = try RelayClient.clientAuth(sock: sock, psk: Array(args[4].utf8))
        print("auth: succeeded")
        let frame = try ch.recv()
        print("recv: \(String(bytes: frame, encoding: .utf8) ?? "<\(frame.count) bytes>")")
        try ch.send(Array("hi-from-swift".utf8))
        ch.close()
    } catch { die("error: \(error)") }

case "connect":
    guard args.count == 6, let port = Int(args[3]) else { die("usage: connect <relay-host> <port> <device> <psk>") }
    do {
        let sock = try RelayClient.connectViaRelay(host: args[2], port: port, deviceId: args[4])
        let ch = try RelayClient.clientAuth(sock: sock, psk: Array(args[5].utf8))
        print("connected + authenticated; receiving frames (ctrl-C to stop)…")
        while true {
            let f = try ch.recv()
            if let t = f.first, t == 0x01, f.count >= 5 {           // MSG_FRAME: [1B][2B w][2B h][jpeg]
                let w = Int(f[1]) << 8 | Int(f[2]), h = Int(f[3]) << 8 | Int(f[4])
                print("frame \(w)x\(h), \(f.count - 5) bytes jpeg")
            } else {
                print("msg type \(f.first ?? 0), \(f.count) bytes")
            }
        }
    } catch { die("error: \(error)") }

default:
    die("unknown command: \(args[1])")
}
