import unittest
from network.packet_send import LinsnLEDSend, LinsnCMDs

## Testing packet sendin
class PacketSendTest(unittest.TestCase):
    def test_check_config_data(self):
        def make_conf_pkt(**kwargs):
            return LinsnLEDSend(cmd=LinsnCMDs.CONFIG, cmd_data=LinsnLEDSend.CmdsConfigData(**kwargs))

        # correct transfer
        cdata = [
            # non-volatile write cmd
            "50 AA 55 AA 99 d8" + ("d8" * 14),
            "90 01 00 00 00 00" + ("d8" * 14),
            "88 01 00 00" + ("aa" * 16),
            "88 01 00 10" + ("bb" * 16),
            "50 AA 55 AA 00 d8" + ("d8" * 14),
            # volatile write cmd
            "50 AA 55 AA 55 d8" + ("d8" * 14),
            "18 01 00 00" + ("aa" * 16),
            "18 01 00 10" + ("bb" * 10),
            "50 AA 55 AA 00 d8" + ("d8" * 14),
        ]

        for i, d in enumerate(cdata):
            p = make_conf_pkt(_pkt=bytes.fromhex(d))
            self.assertTrue(p.check_config_data(), msg=f"Data [{i}]: {d}")

        fdata = [
            "58 AA 55 AA 99 d8" + ("d8" * 14),
            "50 AA 55 AA 77 d8" + ("d8" * 14),
            "98 01 00 00 00 00" + ("d8" * 14),
            "90 01 00 10" + ("bb" * 10),
        ]

        for i, d in enumerate(fdata):
            p = make_conf_pkt(_pkt=bytes.fromhex(d))
            self.assertFalse(p.check_config_data(), msg=f"Data [{i}]: {d}")
