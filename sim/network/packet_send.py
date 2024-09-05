from scapy.all import *
from itertools import accumulate

from network.custom_types import BytesEnum
from network.custom_fields import VerifiablePacket

class LinsnCMDs(BytesEnum):
    MACADDR  = bytes.fromhex('000000000000960000')
    CONFIG   = bytes.fromhex("00000000000061ff00")
    NULL     = bytes.fromhex("000000000000000000")


class LinsnLEDSend(VerifiablePacket):
    name = "LinsnLED Sender Packet"
    fields_desc = [
        # header fields (32 bytes)
        LEShortField("pkg_count", None),
        XStrFixedLenField("cmd", None, 9),
        PacketLenField("cmd_data", None, lambda payload, _parent: LinsnLEDSend.guess_cmd_data_params_class(_parent, payload), lambda _: 20),
        XByteField("chksum", None),  # ?

        # data fields
        XStrFixedLenField("data", None, 1440)
    ]

    def guess_cmd_data_params_class(self, payload):
        match LinsnCMDs(self.cmd):
            case LinsnCMDs.MACADDR:
                return self.CmdMacAddrData(payload)
            case LinsnCMDs.CONFIG:
                return self.CmdsConfigData(payload)
            case LinsnCMDs.NULL:
                return self.CmdNull(payload)

    class CmdsConfigData(Packet):
        fields_desc = [
            FlagsField("flag", None, 3, {0x2: "cmd_bounds"}),  # ?
            XBitField("ones", 0b1, 1),  # ?
            FlagsField("flag2", None, 1, {0x1: "is_data"}),  # ?
            BitField("idx", None, 3),
            XByteField("deli", None),
            XShortField("address", None),  # ?
            XStrFixedLenField("data", None, 16),
        ]

    class CmdMacAddrData(Packet):
        fields_desc = [
            XStrFixedLenField('unknown', bytes.fromhex("00851fffffffff00000000000000"), 14),
            MACField("sender_mac", None),
        ]

    class CmdNull(Packet):
        fields_desc = [
            XStrFixedLenField('null', b"\x00" * 20, 20)
        ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        if self.chksum is None:
            ck = self.checksum(pkt)
            pkt = pkt[:31] + chb(ck) + pkt[32:]
        return super().post_build(pkt, pay)

    @staticmethod
    def checksum(data):
        chk = 0
        for b in data[2:31]:
            chk -= b
        return chk & 0xff

    @VerifiablePacket.is_test
    def check_chksum(self):
        return self.chksum == self.checksum(raw(self))

    @VerifiablePacket.is_test
    def is_valid_command(self):
        return self.cmd in LinsnCMDs

    @VerifiablePacket.is_test
    def enforce_defaults(self):
        # to make it easier for us: instead of taking defaults as a recommendation,
        # we will try to enforce it here. This makes it easy to declare constants
        def _check_fields(pkt: Packet):
            for name, value in pkt.fields.items():
                if isinstance(value, Packet):
                    if not _check_fields(value):
                        return False
                elif (default := pkt.default_fields.get(name, None)) is not None:
                    if value != default:
                        return False
            return True

        return _check_fields(self)

    @VerifiablePacket.is_test
    def check_config_data(self):
        if not isinstance(self.cmd_data, self.CmdsConfigData):
            return True

        # check if any unknown flags
        _unknown_flags = not any("bit_" in v for v in str(self.cmd_data.flag).split("+"))
        _is_bounds = str(self.cmd_data.flag) == "cmd_bounds"

        # check flag2
        _right_flag2 = self.cmd_data.flag2 != _is_bounds
        # check if ones are ones
        _are_ones_ones = self.cmd_data.ones == 0b1
        # check if delimiter in 00 or 0xaa
        _right_deli = self.cmd_data.deli == (0xaa if _is_bounds else 0x00)
        return _unknown_flags and _are_ones_ones and _right_deli and _right_flag2

bind_layers(Ether, LinsnLEDSend, type=0xaa55)
