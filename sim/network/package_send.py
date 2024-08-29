from scapy.all import *

from network.custom_fields import ChoicePacketField, VerifiablePacket

LINSN_LED_BROADCAST_CMD = bytes.fromhex("00000000000096000000851FFFFFFFFF00000000000000")
LINSN_LED_FRAME_CMD     = bytes.fromhex("00000000000096000000850FFFFFFFFF00000000000000")
LINSN_LED_NULL_CMD     = bytes.fromhex("0000000000000000000000000000000000000000000000")


class LinsnLEDSend(VerifiablePacket):
    name = "LinsnLED Send Packet"
    fields_desc = [
        # header fields (32 bytes)
        LEShortField("pkg_count", 0),
        XStrFixedLenField("cmd", None, 23),  # ?
        MACField("sender_mac", None),
        XByteField("checksum", 0),  # ?

        # data fields
        ChoicePacketField("data", '', lambda pkt, p: LinsnLEDSend.guess_data_params_class(pkt, p)),
    ]

    def guess_data_params_class(self, payload):
        if self.cmd == LINSN_LED_BROADCAST_CMD:
            return LinsnLEDSend.Broadcast(payload)
        elif self.cmd in LINSN_LED_NULL_CMD or self.cmd in LINSN_LED_FRAME_CMD:
            return LinsnLEDSend.ImageFrame(payload)
        else:
            raise Exception("Unable to dissect packet")

    class Broadcast(Packet):
        fields_desc = [
            XStrFixedLenField("data", None, 1422),
            XStrFixedLenField("key_exchange", None, 18)  # ?
        ]

    class ImageFrame(Packet):
        fields_desc = [
            XStrFixedLenField("data", None, 1440)
        ]

    @VerifiablePacket.is_test
    def is_valid_command(self):
        return self.cmd in [LINSN_LED_BROADCAST_CMD, LINSN_LED_FRAME_CMD, LINSN_LED_NULL_CMD]

    @VerifiablePacket.is_test
    def is_package_cnt_and_zero_cmd(self):
        return (self.pkg_count > 0) == (self.cmd == LINSN_LED_NULL_CMD)

    @VerifiablePacket.is_test
    def is_data_zeros_for_broadcast_or_frame_cmd(self):
        if self.cmd not in [LINSN_LED_BROADCAST_CMD, LINSN_LED_FRAME_CMD]:
            return True

        return self.data.data is None or all(v == 0 for v in self.data.data)

bind_layers(Ether, LinsnLEDSend, type=0xaa55)
