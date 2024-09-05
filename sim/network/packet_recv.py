#from scapy.all import Packet, XStrFixedLenField, bind_layers, Ether
from scapy.all import *

from network.custom_fields import VerifiablePacket


class LinsnLEDRecv(VerifiablePacket):
    name = "LinsnLED Receiver Packet"

    fields_desc = [
        # header fields
        XStrFixedLenField("m_state", b"\x90\x46\x10" + b"\x00" * 5, 3 + 5),

        # zeros
        XStrFixedLenField("zeros", b"\x00" * (1420 + 6 + 5), 1420 + 6 + 5),

        # data
        #XStrFixedLenField("sync_1", (b"\x55" * 7) + b"\xd5", 8),
        XStrFixedLenField("sync_1", b"HeloLove", 8),
        MACField("sender_mac", None),
        MACField("receiver_mac", None),
        XStrFixedLenField("unknown", None, 6),
        XStrFixedLenField("zeros_2", b"\x00" * 6, 6),

        XStrFixedLenField("sync_2", b"\xf0" * 16, 16),
    ]

    @VerifiablePacket.is_test
    def is_unknown_changing(self):
        unknown_list = [
            bytes.fromhex("aa5690d85880")
        ]
        return self.unknown in unknown_list

    @VerifiablePacket.is_test
    def verify_zeros(self):
        return all(v == 0 for v in self.zeros + self.zeros_2)

    @VerifiablePacket.is_test
    def verify_syncs(self):
        # sync 1
        v_sync_1 = self.sync_1 == self.get_field("sync_1").default

        # sync 2
        v_sync_2 = self.sync_2 == self.get_field("sync_2").default

        return v_sync_1 and v_sync_2

    @VerifiablePacket.is_test
    def is_state_correct(self):
        return self.m_state == self.get_field("m_state").default

bind_layers(Ether, LinsnLEDRecv, type=0xaa56)
