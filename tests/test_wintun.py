"""Root-free Windows adapter and route checks; no driver installation needed."""
import ctypes
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

import tun
import wintun


class TestWindowsRoutes(unittest.TestCase):
    def test_ipv4_and_ipv6_route_commands(self):
        self.assertEqual(wintun._route_cmd("add", "10.2.3.5/24", "remotemac0"),
                         ["netsh", "interface", "ipv4", "add", "route",
                          "prefix=10.2.3.0/24", "interface=remotemac0", "store=active"])
        self.assertEqual(wintun._route_cmd("delete", "2001:db8::/64", "remotemac0")[2],
                         "ipv6")

    def test_configure_adds_overlay_addresses_and_routes(self):
        device = wintun.WintunDevice("remotemac0")
        device._session = 1
        commands = []
        with mock.patch.object(wintun, "_run", side_effect=commands.append), \
             mock.patch.object(wintun.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0)) as run:
            device.configure("100.64.0.2", "100.64.0.0/10", "fd12::2", "fd12::/64")
            self.assertEqual(device._routes, ["100.64.0.0/10", "fd12::/64"])
            device.del_route("fd12::/64")
        self.assertTrue(any("address=100.64.0.2" in cmd for cmd in commands))
        self.assertTrue(any("address=fd12::2/128" in cmd for cmd in commands))
        self.assertTrue(any("prefix=fd12::/64" in cmd for cmd in commands))
        self.assertEqual(run.call_args.args[0][3:5], ["delete", "route"])

    def test_failed_optional_route_is_not_tracked(self):
        device = wintun.WintunDevice()
        with mock.patch.object(wintun.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 1)):
            device.add_route("2001:db8::/64")
        self.assertEqual(device._routes, [])


class TestWindowsPacketIO(unittest.TestCase):
    def test_driver_lifecycle_and_packet_buffers(self):
        dll = mock.Mock()
        dll.WintunCreateAdapter.return_value = 41
        dll.WintunStartSession.return_value = 42
        dll.WintunGetReadWaitEvent.return_value = 43
        kernel = mock.Mock()
        packet = b"\x60" + b"\0" * 39
        recv_buf = ctypes.create_string_buffer(packet)
        send_buf = ctypes.create_string_buffer(len(packet))

        def recv(_session, size_ptr):
            ctypes.cast(size_ptr, ctypes.POINTER(ctypes.c_uint32))[0] = len(packet)
            return ctypes.addressof(recv_buf)
        dll.WintunReceivePacket.side_effect = recv
        dll.WintunAllocateSendPacket.return_value = ctypes.addressof(send_buf)

        def load(name, **_kwargs):
            return kernel if name == "kernel32" else dll
        with mock.patch.object(wintun.os.path, "isfile", return_value=True), \
             mock.patch.object(wintun.ctypes, "WinDLL", side_effect=load, create=True):
            device = wintun.WintunDevice().open()
            self.assertEqual(device.read(), packet)
            device.write(packet)
            self.assertEqual(send_buf.raw, packet)
            device.close()
        dll.WintunReleaseReceivePacket.assert_called_once()
        dll.WintunSendPacket.assert_called_once()
        dll.WintunEndSession.assert_called_once_with(42)
        dll.WintunCloseAdapter.assert_called_once_with(41)

    def test_tun_device_delegates_to_wintun(self):
        fake = mock.Mock()
        fake.open.return_value = fake
        fake.name = "remotemac0"
        fake.read.return_value = b"packet"
        with mock.patch.object(tun.sys, "platform", "win32"), \
             mock.patch.object(wintun, "WintunDevice", return_value=fake):
            dev = tun.TunDevice().open()
            dev.configure("100.64.0.2", overlay_ip6="fd12::2", cidr6="fd12::/64")
            dev.add_route("2001:db8::/64")
            self.assertEqual(dev.read(), b"packet")
            dev.write(b"packet")
            dev.del_route("2001:db8::/64")
            dev.close()
        fake.configure.assert_called_once_with("100.64.0.2", tun.OVERLAY_CIDR,
                                                "fd12::2", "fd12::/64")
        fake.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
