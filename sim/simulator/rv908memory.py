from pathlib import Path
import re
import string
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar, Generic
import types
import numpy as np

T = TypeVar('T')

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


@dataclass
class FourChannelData(Generic[T]):
    channel1: T
    channel2: T
    channel3: T
    channel4: T

    def __init__(self, factory: Callable[[], T], **kwargs) -> None:
        self.channel1 = factory()
        self.channel2 = factory()
        self.channel3 = factory()
        self.channel4 = factory()

        for k,v in kwargs.items():
            self.__setattr__(k, v)

        super().__init__()

    def __getitem__(self, addr):
        return [self.channel1, self.channel2, self.channel3, self.channel4].__getitem__(addr)

    def __setitem__(self, addr, value):
        names = ["channel1", "channel2", "channel3", "channel4"][addr]
        for name in names:
            self.__setattr__(name, value)

@dataclass
class Parameters():
    global_brightness: FourChannelData[int] = field(default_factory=lambda: FourChannelData(int))
    gamma_curves: FourChannelData[list] = field(default_factory=lambda: FourChannelData(list, count=0x100))

class RV908Memory(metaclass=MemoryMeta):
    _LINE_REGEX = re.compile(r"(?P<addr>[0-9a-fA-F]{4}) +(?P<data>(?:\w\w ){15}\w\w) ?(?: ; (?P<desc>(?:([A-Z]=\w+), ?)*(?:[A-Z]=\w+)))?", flags=re.ASCII)
    MEMORY_SIZE = 0x3000
    _parsers: dict[str, Callable[[Any, tuple[int, int], bytes], None]] = {}

    def __init__(self, pattern_file: str | Path, adapt: bool = False, memory_dump_dir: None | Path = None) -> None:

        self._pattern_parsers: dict[tuple[int, int], Callable[[Any, tuple[int, int], bytes], None]] = {}
        self._pattern_arr = bytearray(self.MEMORY_SIZE)

        self._load_pattern(Path(pattern_file))

        self._memory = bytearray(self._pattern_arr)
        self.params = Parameters()
        self._should_adapt = adapt
        self._memory_dump_dir = memory_dump_dir

    def _load_pattern(self, file: Path):
        with open(file, "r") as fp:
            fdata = fp.read()

        pattern_loc = {}
        _current_pattern = None
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
            _line_data = b""
            for pos, elem in enumerate(data.split()):
                if elem[0] not in string.ascii_uppercase and elem[1] not in string.ascii_uppercase:
                    _line_data += bytes.fromhex(elem)
                    _current_pattern = None
                elif (v := elem[0]) == elem[1]:
                    start, end = addr + pos, addr + pos + 1

                    if _current_pattern == v:
                        start = pattern_loc[v][0]
                    elif v in pattern_loc:
                        raise Exception(f"line {idx}: Reuse of pattern {v} in same line")

                    pattern_loc[v] = (start, end)

                    _current_pattern = v
                    _line_data += b"\x00"
                else:
                    raise Exception(f"line {idx}: Unable to parse byte {elem} - should be lower case hex or two same upper case letters for a pattern")

            # check that all descriptions are there (except current active one)
            if set(pattern_loc) - {_current_pattern} != set(desc) - {_current_pattern}:
                raise Exception(f"line {idx}: Not all descriptions are mentioned in the hex or vice versa (data: {set(pattern_loc)} | desc: {set(desc)})")

            # add line data to pattern bytes
            self._pattern_arr[addr:addr + 16] = _line_data

            # add to global area -> description parser dictionary
            for k, v in desc.items():
                _parser = self._parsers.get(v)
                if _parser is None:
                    raise Exception(f"line {idx}: Unknown description parser `{v}`")
                self._pattern_parsers[pattern_loc[k]] = _parser

                # clear temporaries
                del pattern_loc[k]  # will clear pattern_loc except for _current_pattern if that is not in desc
                if _current_pattern == k:  # clear current_pattern, if there is a desc. def. for it here
                    _current_pattern = None

    def parse(self):
        for (s, e), f in self._pattern_parsers.items():
            f(self, (s, e), self._memory[s:e])

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

    def store_dump(self):
        if self._memory_dump_dir is None or not self._memory_dump_dir.is_dir():
            print("Error writing memory dump")
            return
        # determine max idx
        max_idx = -1
        for f in self._memory_dump_dir.iterdir():
            if (m := re.match(r"(\d+).bin", f.name)):
                max_idx = max(max_idx, int(m.group(1)))

        # write to next free idx
        name = f"{max_idx + 1:04}.bin"
        with (self._memory_dump_dir / name).open("wb") as fp:
            fp.write(self._memory)

        print(f"-- Written memory dump to {name}")

    #############################################
    ##                PARSERS                  ##
    #############################################

    @parameter_parser
    def global_brightness(self, _: tuple[int, int], v: bytes):
        for i, brightness in enumerate(v):
            self.params.global_brightness[i] = brightness

    @parameter_parser
    def gamma_curve(self, addr: tuple[int, int], v: bytes):
        # get channel by looking at the address of the data
        i = [0x2000, 0x2800, 0x2A00, 0x2C00].index(addr[0])
        if i == -1:
            raise IndexError(f"unknown starting address area for gamma {addr[0]} ({addr})")

        # parse the data
        lookup = np.frombuffer(v, dtype=np.uint16)

        # verify data
        if len(lookup) != self.params.gamma_curves.count:
            raise Exception(f"Invalid size. Expected {self.params.gamma_curves.count}, got {len(lookup)}")

        self.params.gamma_curves[i] = list(lookup)
