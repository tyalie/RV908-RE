from enum import Enum
from typing import Callable, Awaitable
from pathlib import Path
from statemachine import StateMachine
from statemachine.statemachine import InvalidDefinition, StateMachineMetaclass
from statemachine.states import States, State
from network import LinsnLEDRecv
from scapy.all import Packet, Ether

from simulator.rv908memory import RV908Memory, VerificationException


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
        self.in_command_setting = False

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

    def recv_memory_setting(self, is_bound: bool, pkt_idx: int, addr: int, data: bytes):
        if self._prev_cmd_idx == pkt_idx:
            return  # cmd packages are send repeatedly and often
        self._prev_cmd_idx = pkt_idx

        if is_bound:
            if data[0] == 0x55:  # start
                if self.in_command_setting:
                    print("Already inside command. What happend?")
                else:
                    self.in_command_setting = True
                print("Memory Update:")
            elif data[0] == 0x00:  # end
                if not self.in_command_setting:
                    print("Already outside command. What happend?")
                else:
                    self._memory.store_dump()
                    self.in_command_setting = False

                self._memory.parse()
            else:
                raise Exception(f"Unknown state for bound cmd {data[0]}")
        else:
            print(f"{addr:04X}  {data.hex(' ')}")
            try:
                self._memory[addr:addr+16] = data
            except VerificationException as e:
                print("- error:", str(e))
