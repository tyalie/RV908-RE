"""
Handling of the network interface (here tap interface)
and parsing of that data.
"""
from io import FileIO
import aiofile
import struct
import fcntl
import asyncio
from pyshark.packet.packet import Packet
import pyshark

MTU_USED = 1500

class NetworkSocket:
    def __init__(self, tap_name: str):
        self.tap_name : bytes = tap_name.encode("ascii")
        self.tap_dev : None | aiofile.BinaryFileWrapper = None
        self.memcap = pyshark.InMemCapture()

    def open(self):
        if self.tap_dev is not None:
            raise RuntimeError("TAP device is already open")
            
        tap_fd = open("/dev/net/tun", "r+b", buffering=0)
        LINUX_IFF_TAP = 0x0002
        LINUX_IFF_NO_PI = 0x1000
        LINUX_TUNSETIFF = 0x400454CA
        flags = LINUX_IFF_TAP | LINUX_IFF_NO_PI
        ifs = struct.pack("16sH22s", self.tap_name, flags, b"")
        fcntl.ioctl(tap_fd, LINUX_TUNSETIFF, ifs)
        _dev = aiofile.async_open(tap_fd)

        assert isinstance(_dev, aiofile.BinaryFileWrapper), "Incorrect file mode (not binary)"

        self.tap_dev = _dev

    async def close(self):
        if self.tap_dev is not None:
            await self.tap_dev.close()
            self.tap_dev = None

    async def receive_package(self) -> Packet:
        _dev = self.tap_dev
        if _dev is None:
            raise RuntimeError("Net Device is closed")

        # the ethernet frame has at most 22 bytes of additional data
        rdata = await _dev.read(MTU_USED + 22)
        pdata = await self.memcap.parse_packets_async([rdata])
        
        assert len(pdata) == 1, "Invalid state: Not exactly one packet parsed"

        return pdata[0]

    async def __aenter__(self):
        self.open()

    async def __aexit__(self, type, value, traceback):
        await self.close()
