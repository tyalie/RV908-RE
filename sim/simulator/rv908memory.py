from pathlib import Path
import re
from scapy.all import hexdump
import string
import dataclasses
from typing import Any, Callable
import types


class VerificationException(Exception):
    def __init__(self, message: str, addr: int) -> None:
        self.addr = addr
        super().__init__(message)

def parameter_parser(func):
    func.__setattr__("is_parameter", True)
    return func

class MemoryMeta(type):
    def __new__(cls, name: str, bases: tuple[type, ...], namespace: dict[str, Any]):
        parsers = {}
        for k, v in namespace.items():
            if isinstance(v, types.FunctionType) and v.__dict__.get("is_parameter"):
                parsers[k] = v

        namespace["_parsers"] = parsers
        return super().__new__(cls, name, bases, namespace)


class RV908Memory(metaclass=MemoryMeta):
    _LINE_REGEX = re.compile(r"(?P<addr>[0-9a-fA-F]{4}) +(?P<data>(?:\w\w ){15}\w\w) ?(?: ; (?P<desc>(?:([A-Z]=\w+), ?)*(?:[A-Z]=\w+)))?", flags=re.ASCII)
    MEMORY_SIZE = 0x3000
    _parsers: dict[str, Callable[[bytes], None]] = {}

    @dataclasses.dataclass
    class Parameters():
        global_brightness: int = 0

    def __init__(self, pattern_file: str | Path, adapt: bool = False) -> None:

        self._pattern_parsers = {}
        self._pattern_arr = bytearray(self.MEMORY_SIZE)

        self._load_pattern(Path(pattern_file))

        self._memory = bytearray(self._pattern_arr)
        self.params = RV908Memory.Parameters()
        self._should_adapt = adapt

    def _load_pattern(self, file: Path):
        with open(file, "r") as fp:
            fdata = fp.read()

        for idx, line in enumerate(fdata.splitlines(), start=1):
            if line.strip().startswith("#"):
                # ignore comment
                continue

            p = RV908Memory._LINE_REGEX.fullmatch(line)
            if p is None:
                raise Exception(f"line {idx}: Can't match regex `^{RV908Memory._LINE_REGEX.pattern}$`")

            # parse a line
            addr = int(p.group("addr"), 16)
            data = p.group("data")
            desc = {}
            if p.group('desc') is not None:
                desc = {(v := elem.strip().split("="))[0]: v[1] for elem in p.group("desc").split(",")}

            # find and replace data substitutions
            pattern_loc = {}
            _cur_pat = None
            _line_data = b""
            for pos, elem in enumerate(data.split()):
                if elem[0] not in string.ascii_uppercase and elem[1] not in string.ascii_uppercase:
                    _line_data += bytes.fromhex(elem)
                elif (v := elem[0]) == elem[1]:
                    start, end = addr + pos, addr + pos + 1
                    if _cur_pat == v:
                        start = pattern_loc[v][0]

                    pattern_loc[v] = (start, end)

                    _cur_pat = v
                    _line_data += b"\x00"
                else:
                    raise Exception(f"line {idx}: Unable to parse byte {elem} - should be lower case hex or two same upper case letters for a pattern")

            if set(pattern_loc) != set(desc):
                raise Exception(f"line {idx}: Not all descriptions are mentioned in the hex or vice versa (data: {set(pattern_loc)} | desc: {set(desc)})")

            # add line data to pattern bytes
            self._pattern_arr[addr:addr + 16] = _line_data

            # add to global area -> description parser dictionary
            for k, v in desc.items():
                _parser = self._parsers.get(v)
                if _parser is None:
                    raise Exception(f"line {idx}: Unknown description parser `{v}`")
                self._pattern_parsers[pattern_loc[k]] = _parser

    def parse(self):
        for (s, e), f in self._pattern_parsers.items():
            f(self, self._memory[s:e])

    def verify_memory(self, start: None | int = None, end: None | int = None):
        def in_some_range(idx: int) -> bool:
            for (s, e) in self._pattern_parsers:
                if s <= idx and idx < e:
                    return True
            return False

        assert len(self._memory) == len(self._pattern_arr), "Mismatching size between pattern and memory"

        start = 0 if start is None else start
        end = len(self._memory) if end is None else end

        for idx in range(start, end):
            if self._memory[idx] != self._pattern_arr[idx] and not in_some_range(idx):
                raise VerificationException(f"Verification failed - mismatch at addr 0x{idx:04X} (excepted: 0x{self._pattern_arr[idx]:02X} | got: 0x{self._memory[idx]:02X})", idx)

    def __getitem__(self, addr):
        return self._memory.__getitem__(addr)

    def __setitem__(self, addr, value):
        self._memory.__setitem__(addr, value)

        try:
            if isinstance(addr, slice):
                self.verify_memory(addr.start, addr.stop)
            else:
                self.verify_memory(addr, addr + 1)
        finally:
            if self._should_adapt:
                self._pattern_arr[addr] = value

        self.parse()

    #############################################
    ##                PARSERS                  ##
    #############################################

    @parameter_parser
    def global_brightness(self, v: bytes):
        self.params.global_brightness = v[0]
