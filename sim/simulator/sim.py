from scapy.all import Packet, PcapWriter

import random
from network import NetworkSocket, LinsnLEDSend
from network.packet_recv import LinsnLEDRecv
from simulator.statemachine import RV908StateMachine
from ui import StatusWindowProcess

class Simulator():
    def __init__(self, socket: NetworkSocket, with_gui: bool = True, adapt_memory: bool = False) -> None:
        self._socket = socket
        self._gui: None | StatusWindowProcess = None
        if with_gui:
            self._gui = StatusWindowProcess()

        self._sm = RV908StateMachine(receiver_mac="01:23:45:67:89:ab")
        self._sm.register_send_cbk(self._socket.send_package)

        self._pcapw = PcapWriter("failed_packages.pcap")

    def start_ui(self):
        if self._gui is None:
            return

        self._gui.start()
        self._gui.set_matrix_size(1024, 512)

    def _write_pkt_to_file(self, pkt: Packet):
        self._pcapw.write(pkt)
        self._pcapw.flush()

    async def run(self):
        async with self._socket:
            while True:
                data = await self._socket.receive_package()
                if type(data) == tuple:
                    # we received an frame segment -> send it to GUI
                    if self._gui is None:
                        continue
                    self._gui.receive_data((data[0]) * 1440, data[1])
                elif isinstance(data, Packet):
                    if LinsnLEDSend in data:
                        await self._handle_linsn_send_data(data.payload)
                    elif LinsnLEDRecv in data:
                        await self._handle_linsn_recv_data(data.payload)
                    else:
                        print(f"unknown package received - ignoring {data}")
                        #data.show()

    async def _handle_linsn_recv_data(self, pkg: LinsnLEDRecv):
        is_valid, failures = pkg.verify()
        if not is_valid:
            pkg.show()
            print(failures)
            self._write_pkt_to_file(pkg.underlayer)
            return

        pkg.show()

    async def _handle_linsn_send_data(self, pkg: LinsnLEDSend):
        is_valid, failures = pkg.verify()
        if not is_valid:
            pkg.show()
            print(failures)
            self._write_pkt_to_file(pkg.underlayer)
            return

        if pkg.parent is not None and pkg.parent.dst == "ff:ff:ff:ff:ff:ff":
            await self._sm.recv_discovery_broadcast(pkg.sender_mac)
        else:
            ...
