from enum import Enum
from typing import Callable, Awaitable
from pathlib import Path
from statemachine import StateMachine
from statemachine.statemachine import InvalidDefinition, StateMachineMetaclass
from statemachine.states import States, State
from network import LinsnLEDRecv
from scapy.all import Packet, Ether
from network.packet_send import LinsnLEDSend

from simulator.rv908memory import RV908Memory, VerificationException

class StateException(Exception):
    ...

class WrongDelimiterStateException(StateException):
    ...

class CustomStateMachine(StateMachineMetaclass):
    """
    During RE I'll introduce a lot of states that will only be connected over time,
    as the transitions are not known yet. So a strict policy of "no unconnected states",
    is really annoying. Instead throw a warning but nothing else please
    """

    def _check_disconnected_state(cls):
        try:
            super()._check_disconnected_state()
        except InvalidDefinition as e:
            print("Discovered disconnected states:")
            for disconnected in cls._disconnected_states(cls.initial_state):
                print(f"  - {disconnected.id}")


class RV908StateMachine(StateMachine, metaclass=CustomStateMachine):
    class Status(Enum):
        BEGIN = "bootup"

        WAITING_4_DISCOVERY = "Waiting for sender discovery"
        DISCOVERY = "Sender discovery is happening"

        WAITING_4_FRAME = "Waiting for image frame"
        RECEIVING_FRAME = "Receiving frame"

        CONFIG = "Configure receiver"  # unknown if an actual state

        SHUTDOWN = "device is off"

    states = States.from_enum(Status, Status.BEGIN, Status.SHUTDOWN, use_enum_instance=True)

    # bootup our 'FPGA'
    init = states.BEGIN.to(states.WAITING_4_DISCOVERY)

    # we got a "who is there?" broadcast from the sender -> need to answer
    recv_discovery_broadcast = states.WAITING_4_DISCOVERY.to(states.DISCOVERY) | states.DISCOVERY.to.itself()

    recv_frame_header = states.DISCOVERY.to(states.RECEIVING_FRAME) \
        | states.RECEIVING_FRAME.to.itself() \
        | states.WAITING_4_FRAME.to(states.RECEIVING_FRAME)

    frame_end = states.RECEIVING_FRAME.to(states.WAITING_4_FRAME)


    def __init__(self, receiver_mac: str, memory: RV908Memory, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.receiver_mac : str = receiver_mac
        self._callback : None | Callable[[Packet], Awaitable[None]] = None

        self._sender_mac : None | bytes = None

        self._memory = memory
        self._prev_cmd_idx = None
        self.in_transfer_type = 0

        self.init()  # initialise system


    def on_enter_state(self, event, state: State):
        print(f"Entering `{state.id} state from `{event}` event.")

    def register_send_cbk(self, callback: Callable[[Packet], Awaitable[None]]):
        self._callback = callback

    def remove_send_cbk(self):
        self._callback = None

    async def _send_msg(self, pkg: Packet):
        if self._callback is None:
            print(f"Couldn't send {pkg}, because no callback provided")
            return

        await self._callback(pkg)

    @recv_discovery_broadcast.on
    async def send_broadcast_feedback(self, sender_mac: bytes):
        self._sender_mac = sender_mac

        pkt = Ether(src=self.receiver_mac, dst=self._sender_mac) / LinsnLEDRecv(
            sender_mac = self._sender_mac,
            receiver_mac = self.receiver_mac,
            unknown = bytes.fromhex("aa5690d85880")
        )

        await self._send_msg(pkt)

    def recv_memory_setting(self, confd: LinsnLEDSend.CmdsConfigData, printout: bool = True):
        if self._prev_cmd_idx == confd.idx:
            return  # cmd packages are send repeatedly and often
        self._prev_cmd_idx = confd.idx

        if printout:
            self.print_memory_update(confd)

        try:
            match confd.type_e:
                case confd.TypeEnum.CONF if confd.data[0] in [0x55, 0x99]:
                    # start of transfer
                    if self.in_transfer_type:
                        raise WrongDelimiterStateException(f"Already inside command", confd)
                    self.in_transfer_type = confd.data[0]
                case confd.TypeEnum.CONF if confd.data[0] == 0x00:
                    # end of transfer / store and parse
                    if not self.in_transfer_type:
                        raise WrongDelimiterStateException(f"Already outside command", confd)
                    else:
                        self._memory.store_dump()
                        self.in_transfer_type = 0

                    self._memory.parse()
                case confd.TypeEnum.PERM_CONF if confd.data[0:2] == b"\x00\x00" and self.in_transfer_type == 0x99:
                    # erase 4kiB
                    self._memory[confd.address:confd.address + 0x1000] = b"\xFF" * 0x1000
                case v if v == {0x55: confd.TypeEnum.TMP_DATA, 0x99: confd.TypeEnum.PERM_DATA}.get(self.in_transfer_type, None):
                    # data is being written
                    self._memory[confd.address:confd.address+16] = confd.data
                case _:
                    raise StateException(f"Unknown state", confd)
        except VerificationException as e:
            print("- error:", str(e))

    def print_memory_update(self, confd):
        _ = f"{confd.idx:1X} {confd.type_e.short_name():>2}|"
        _ += "D" if confd.is_data else " "
        _ += "|"

        print(_, end="")
        print(f"{confd.address:06X}  {confd.data.hex(' ')}")
