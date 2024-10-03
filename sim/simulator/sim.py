from scapy.all import Packet, PcapWriter, IP, IPv6

from pathlib import Path
from network import NetworkSocket, LinsnLEDSend
from network.packet_recv import LinsnLEDRecv
from simulator.statemachine import RV908StateMachine
from simulator.rv908memory import RV908Memory
from ui import StatusWindowProcess

class Simulator():
    def __init__(self, socket: NetworkSocket, with_gui: bool = True, adapt_memory: bool = False, tmp_folder: Path = Path("./")) -> None:
        self._socket = socket
        self._gui: None | StatusWindowProcess = None
        if with_gui:
            self._gui = StatusWindowProcess()

        self._memory = RV908Memory(Path(__file__).parent / "./memory.hex", adapt_memory, memory_dump_dir=tmp_folder)

        self._sm = RV908StateMachine(receiver_mac="01:23:45:67:89:ab", memory=self._memory)
        self._sm.register_send_cbk(self._socket.send_package)

        self._pcapw = PcapWriter(str(tmp_folder / "failed_packages.pcap"))

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
                    elif IP in data or IPv6 in data:
                        ...
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

        if pkg.underlayer is not None and pkg.underlayer.dst == "ff:ff:ff:ff:ff:ff":
            await self._sm.recv_discovery_broadcast(pkg.cmd_data.sender_mac)
        elif isinstance(pkg.cmd_data, LinsnLEDSend.CmdsConfigData):
            confd: LinsnLEDSend.CmdsConfigData = pkg.cmd_data
            self._sm.recv_memory_setting(str(confd.flag) == "cmd_bounds", confd.idx, confd.address, confd.data)
