from scapy.all import Packet

from network import NetworkSocket
from ui import StatusWindowProcess


class Simulator():
    def __init__(self, socket: NetworkSocket) -> None:
        self._socket = socket
        self._gui = StatusWindowProcess()

    def start_ui(self):
        self._gui.start()
        self._gui.set_matrix_size(1024, 512)

    async def run(self):
        async with self._socket:
            while True:
                data = await self._socket.receive_package()
                if type(data) == tuple:
                    # we received an frame segment -> send it to GUI
                    self._gui.receive_data((data[0]) * 1440, data[1])
                elif isinstance(data, Packet):
                    print(f"package")
                    data.show()
