from scapy.all import *
from itertools import accumulate

from enum import Enum, unique
from network.custom_types import BytesEnum
from network.custom_fields import VerifiablePacket

class LinsnCMDs(BytesEnum):
    MACADDR  = bytes.fromhex('00000000000096')
    CONFIG   = bytes.fromhex("00000000000061")
    NULL     = bytes.fromhex("00000000000000")


class LinsnLEDSend(VerifiablePacket):
    name = "LinsnLED Sender Packet"
    fields_desc = [
        # header fields (32 bytes)
        LEShortField("pkg_count", None),
        XStrFixedLenField("cmd", None, 7),
        ShortField("panel_idx", None),
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
        @unique
        class TypeEnum(Enum):
            TMP_DATA  = 0x1
            CONF      = 0x5
            PERM_DATA = 0x8
            PERM_CONF = 0x9

            def short_name(self):
                return "".join(map(lambda s: s[0].upper(), self.name.split("_")))

        fields_desc = [
            BitEnumField("type", None, 4, TypeEnum),
            BitField("is_data", None, 1),
            BitField("idx", None, 3),
            X3BytesField("address", None),
            XStrFixedLenField("data", None, 16),
        ]

        @property
        def type_e(self) -> None | TypeEnum:
            try:
                return self.TypeEnum(self.type)
            except ValueError:
                return None

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
    def is_panel_idx_right(self):
        return self.cmd == LinsnCMDs.CONFIG or self.panel_idx == 0

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

        """ The memory transfer protocol

        I EEE D| AAAAAA  SS rest-of-the-data …
        I: Idx [0-7]/ E: package type enum /
        D: Data / A: Address / S: Starting byte [part of the data]

        D is a bit flags, I, E and A are integers
        """

        is_correct = True
        match self.CmdsConfigData.type_e:
            case self.CmdsConfigData.TypeEnum.CONF:
                # transfer start or end
                is_correct &= self.cmd_data.is_data == 0
                is_correct &= self.cmd_data.address == 0xAA55AA
                is_correct &= self.cmd_data.data[0] in [0x55, 0x99, 0x0]
                is_correct &= self.cmd_data.data[1:] == b"\xd8" * 15
            case self.CmdsConfigData.TypeEnum.PERM_CONF:
                # config used for permanent sequences (currently only erase is known)
                is_correct &= self.cmd_data.is_data == 0
                # erase has only been observed with 4kiB aligned step size
                is_correct &= (self.cmd_data.address % 0x1000) == 0
                # this presumably means erase
                is_correct &= self.cmd_data.data[0:2] == b"\x00\x00"
                is_correct &= self.cmd_data.data[2:] == b"\xd8" * 14
            case self.CmdsConfigData.TypeEnum.TMP_DATA:
                # temporary data
                is_correct &= self.cmd_data.is_data == 1
            case self.CmdsConfigData.TypeEnum.PERM_DATA:
                # permanent data
                is_correct &= self.cmd_data.is_data == 1
            case _:
                is_correct = False

        return is_correct


bind_layers(Ether, LinsnLEDSend, type=0xaa55)
