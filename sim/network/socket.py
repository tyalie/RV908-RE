"""
Handling of the network interface (here tap interface)
and parsing of that data.
"""
import aiofile
import struct
import fcntl
from .package_send import LinsnLEDSend  # we need this, as otherwise it isn't registered
from scapy.all import Ether, Packet

MTU_USED = 1500

class NetworkSocket:
    def __init__(self, tap_name: str):
        self.tap_name : bytes = tap_name.encode("ascii")
        self.tap_dev : None | aiofile.BinaryFileWrapper = None

    def open(self):
        if self.tap_dev is not None:
            raise RuntimeError("TAP device is already open")

        # init our tap ethernet device, the device itself needs
        # to be created beforehand
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

    async def receive_package(self) -> Packet | tuple[int, bytes]:
        _dev = self.tap_dev
        if _dev is None:
            raise RuntimeError("Net Device is closed")

        while True:
            # the ethernet frame has at most 22 bytes of additional data
            rdata = await _dev.read(MTU_USED + 22)

            # parsing a package is quite resource intensive on a scale of <100us per package.
            # As the bulk (>99%) of packets are very simple image frames, we can add an exception
            # for handling these and parse them significantly quicker, giving us ample time to
            # fully parse and validate these packets that require our attention.
            # protocol = 0xaa55
            # first 32 bytes of data (except pkg num) are zeros
            if rdata[12] == 0xaa and rdata[13] == 0x55 and rdata[16:48 - 2] == b'\x00'*30:
                # skipped package because it's one of these image frames
                return int.from_bytes(rdata[14:16], "little", signed=False), rdata[48:]

            return Ether(rdata)

    async def __aenter__(self):
        self.open()

    async def __aexit__(self, type, value, traceback):
        await self.close()
