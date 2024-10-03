from pathlib import Path
import re
import copy
import string
from dataclasses import dataclass, field
import itertools
from typing import Any, Callable, TypeVar, Generic, MutableSequence, Iterator
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

class SparseMemory(Generic[T]):
    """
    the linsn receivers have volatile and non-volatile memory.
    This is used quite often by Linsn for their temporary and
    permentant testing and deploying of configuration data.
    Presumably to simplify the loading portion, they only change
    the highest byte which means that the data layout and addr (& 0xFFFF)
    stay the same. Using a mapping between these areas we can spot diffs
    and keep our memory.hex in sync.
    """

    def __init__(self, *ignore, memory: dict[tuple[int, int], MutableSequence[T]] = {}) -> None:
        if ignore:
            raise TypeError

        self._memory: dict[tuple[int, int], MutableSequence[T]] = memory

    @classmethod
    def from_layout(cls, layout: dict[tuple[int, int], str], init_func: Callable[[int], MutableSequence[T]]):
        inst = cls()

        def intersect(r1, r2):
            return max(r1[0],r2[0]) <= min(r1[1],r2[1])

        for x,y in itertools.combinations(layout, 2):
            if intersect(x, y):
                raise ValueError(f"Ranges {x} and {y} are overlapping")

        _tmp = {}
        for r, name in layout.items():
            _len = r[1] - r[0]
            if _len < 0:
                raise Exception(f"Size should be larger than 0 bytes (got: {_len})")
            inst._memory[r] = _tmp.setdefault(name, init_func(_len))
        return inst

    @property
    def ranges(self) -> list[tuple[int, int]]:
        return sorted(self._memory, key=lambda v: v[1])

    def idx_iter(self) -> Iterator[int]:
        for s, e in self.ranges:
            yield from range(s, e)

    def _getsubarray(self, addr: int | slice) -> MutableSequence[T]:
        if isinstance(addr, slice):
            _start, _end = addr.start, addr.stop
        else:
            _start, _end = addr, addr

        if _end < _start:
            _start, _end = _end, _start

        for r in self.ranges:
            if r[0] <= _start and _end <= r[1]:
                return self._memory[r]

        raise IndexError(f"Couldn't find continous memory segment for slice({_start:06X}, {_end:06X})")

    def __getitem__(self, addr):
        return self._getsubarray(addr)[addr]

    def __setitem__(self, addr, value):
        _l = self._getsubarray(addr)
        if isinstance(addr, slice) and len(_l[addr]) != len(value):
            raise ValueError(f"Size mismatch between size and given slice")
        _l[addr] = value

    def __copy__(self):
        import copy

        n_memory, _tmp = {}, {}
        for r, v in self._memory.items():
            n_memory[r] = _tmp.setdefault(id(v), copy.copy(v))
        return self.__class__(memory=n_memory)

    def non_sparse(self, empty_init: Callable[[int], MutableSequence[T]]) -> MutableSequence[T]:
        # empty output
        out = empty_init(0)

        cur_idx = 0
        breakpoint()
        for r in self.ranges:
            if cur_idx < r[0]:
                out += empty_init(r[0] - cur_idx)

            cur_idx = r[1]
            out += self._memory[r]

        return out

@dataclass
class Parameters():
    global_brightness: FourChannelData[int] = field(default_factory=lambda: FourChannelData(int))
    gamma_curves: FourChannelData[list] = field(default_factory=lambda: FourChannelData(list, count=0x100))

class RV908Memory(metaclass=MemoryMeta):
    _LINE_REGEX = re.compile(r"(?P<addr>[0-9a-fA-F]{6}) +(?P<data>(?:\w\w ){15}\w\w) ?(?: ; (?P<desc>(?:([A-Z]=\w+), ?)*(?:[A-Z]=\w+)))?", flags=re.ASCII)
    _parsers: dict[str, Callable[[Any, tuple[int, int], bytes], None]] = {}

    def __init__(self, pattern_file: str | Path, adapt: bool = False, memory_dump_dir: None | Path = None) -> None:

        self._pattern_parsers: dict[tuple[int, int], Callable[[Any, tuple[int, int], bytes], None]] = {}
        self._memory_pat = SparseMemory.from_layout({
            (0x000000, 0x002F00): "display config",
        }, bytearray)
        self._memory_mask = copy.copy(self._memory_pat)

        self._load_pattern(Path(pattern_file))

        self._memory = copy.copy(self._memory_pat)
        self._should_adapt = adapt
        self._memory_dump_dir = memory_dump_dir

        self.params = Parameters()

    def _load_pattern(self, file: Path):
        with open(file, "r") as fp:
            fdata = fp.read()

        pattern_loc = {}
        _current_pattern = None
        for idx, line in enumerate(fdata.splitlines(), start=1):
            if line.strip().startswith("#") or len(line.strip()) == 0:
                # ignore comment or empty lines (used as visual markers)
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
            self._memory_pat[addr:addr + 16] = _line_data

            # add to global area -> description parser dictionary
            for k, v in desc.items():
                _parser = self._parsers.get(v)
                if _parser is None:
                    raise Exception(f"line {idx}: Unknown description parser `{v}`")

                _loc = pattern_loc[k]
                self._pattern_parsers[_loc] = _parser
                self._memory_mask[_loc[0]:_loc[1]] = b'\x01' * (_loc[1] - _loc[0])

                # clear temporaries
                del pattern_loc[k]  # will clear pattern_loc except for _current_pattern if that is not in desc
                if _current_pattern == k:  # clear current_pattern, if there is a desc. def. for it here
                    _current_pattern = None

    def parse(self):
        for (s, e), f in self._pattern_parsers.items():
            f(self, (s, e), self._memory[s:e])

    def verify_memory(self, start: int, end: int):
        for idx in range(start, end):
            if self._memory[idx] != self._memory_pat[idx] and not self._memory_mask[idx]:
                raise VerificationException(f"Verification failed - mismatch at addr 0x{idx:04X} (excepted: 0x{self._memory_pat[idx]:02X} | got: 0x{self._memory[idx]:02X})", idx)

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
                self._memory_pat[addr] = value

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
            fp.write(self._memory.non_sparse(bytearray))

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
