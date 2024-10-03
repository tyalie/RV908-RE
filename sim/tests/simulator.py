import unittest
from unittest.mock import MagicMock, call
from simulator.statemachine import RV908StateMachine, StateException
from network.packet_send import LinsnLEDSend

class StateMachineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.memory = MagicMock()
        self.sm = RV908StateMachine("00:00:00:00:00:00", self.memory)

    def test_memory_received(self):
        def get_params(s: str):
            return LinsnLEDSend.CmdsConfigData(bytes.fromhex(s))

        """
        seqs specifies all test cases. The layout is:
            seqs: dict[key, tuple[seq: list[data], tests: dict[func, calls: list[args: tuple[any]]]]]
        with
            - key: name of the test. Starts with ! if a failure one
            - seq: The byte sequence to replay (list of strings)
                - data: a hex string representing a byte object ofr a single line. if it starts with ! this line is supposed to raise an exception
            - tests: the tests after the sequence for the mock object
                - func: the mock function to operate on
                - calls: list of arguments for each calling instance
        """
        seqs = {
            "non volatile erase": ([
                "50 AA 55 AA 99 d8" + ("d8" * 14),
                "91 01 00 00 00 00" + ("d8" * 14),
                "52 AA 55 AA 00 d8" + ("d8" * 14),
            ], {
                self.memory.__setitem__: [(slice(0x10_000, 0x11_000), b"\xFF" * 0x1000)],
                self.memory.store_dump: [tuple()],
                self.memory.parse: [tuple()]
            }),
            "non volatile write": ([
                "50 AA 55 AA 99 d8" + ("d8" * 14),
                "91 00 10 00 00 00" + ("d8" * 14),
                "8A 00 10 00" + ("aa" * 16),
                "8B 00 10 10" + ("bb" * 16),
                "54 AA 55 AA 00 d8" + ("d8" * 14),
            ], {
                self.memory.__setitem__: [(slice(0x1000, 0x2000), b"\xFF" * 0x1000), (slice(0x1000, 0x1010), b"\xaa" * 16), (slice(0x1010, 0x1020), b"\xbb" * 16)],
                self.memory.store_dump: [tuple()],
                self.memory.parse: [tuple()]
            }),
            "volatile write": ([
                "50 AA 55 AA 55 d8" + ("d8" * 14),
                "19 00 00 00" + ("aa" * 16),
                "52 AA 55 AA 00 d8" + ("d8" * 14),
            ], {
                self.memory.__setitem__: [(slice(0x0, 0x10), b"\xaa" * 16)],
                self.memory.store_dump: [tuple()],
                self.memory.parse: [tuple()]
            }),
            "!write vol->nonvol": ([
                "50 AA 55 AA 55 d8" + ("d8" * 14),
                "!91 00 00 00 00 00" + ("d8" * 14),  # marking an excpetion line with !
                "!9a 00 00 00" + ("aa" * 16),
                "53 AA 55 AA 00 d8" + ("d8" * 14),
            ], {
                self.memory.store_dump: [tuple()],
                self.memory.parse: [tuple()]
            }),
            "!write no-start": ([
                "!91 00 00 00 00 00" + ("d8" * 14),
                "!9a 00 00 00" + ("aa" * 16),
                "!53 AA 55 AA 00 d8" + ("d8" * 14),
            ], {})
        }

        for key, (seq, funcs) in seqs.items():
            with self.subTest(key=key):
                self.memory.reset_mock()
                for p in seq:
                    if p[0] == '!':
                        self.assertRaises(StateException, self.sm.recv_memory_setting, get_params(p[1:]), printout=False)
                    else:
                        self.sm.recv_memory_setting(get_params(p), printout=False)

                for func, params in funcs.items():
                    self.assertEqual(func.call_count, len(params), msg=f"Expected {params}\nGot: {func.call_args_list}")
                    func.assert_has_calls(
                        map(lambda v: call(*v) , params),
                        any_order=False
                    )
