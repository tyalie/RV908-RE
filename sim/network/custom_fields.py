from scapy.all import Packet_metaclass, PacketField, Packet, AnyField, Field
from typing import TypeVar, Callable, Generic, Any
import types

I = TypeVar('I')  # Internal storage  # noqa: E741
M = TypeVar('M')  # Machine storage

class GeneratedField(Generic[I,M], Field[I, M]):
    __slots__ = ["method"]

    def __init__(self, name, method: Callable[[Packet], I]):
        self.method: Callable[[Packet], I] = method
        Field.__init__(self, name, 0, "H")

    def calc(self, pkg: Packet) -> I:
        return self.method(pkg)

    def addfield(self, pkt: Packet, s: bytes, val: None | I) -> bytes:
        return s


class PacketWithGenerated(Packet):
    def getfieldval(self, attr: str) -> Any:
        _, v = self.getfield_and_val(attr)
        return v

    def getfield_and_val(self, attr: str) -> tuple[AnyField, Any]:
        f, v = super().getfield_and_val(attr)

        if isinstance(f, GeneratedField):
            v = f.calc(self)

        return f, v

class CollectTests(Packet_metaclass):
    def __new__(cls, name: str, bases: tuple[type, ...], namespace: dict[str, Any]):
        namespace["_tests"] = []
        for v in namespace.values():
            if isinstance(v, types.FunctionType) and v.__dict__.get("is_test"):
                namespace["_tests"].append(v)

        if "fields_desc" in namespace:
            namespace["fields_desc"].append(
                GeneratedField[bool, bool]("is_valid", lambda p: VerifiablePacket.verify(p)[0])
            )

        return super().__new__(cls, name, bases, namespace)

class VerifiablePacket(PacketWithGenerated, metaclass=CollectTests):
    _tests: list[Callable] = []

    @staticmethod
    def is_test(func):
        func.__setattr__("is_test", True)
        return func

    def verify(self) -> tuple[bool, list[Callable]]:
        failed_tests = []

        for f in self._tests:
            if not f(self):
                failed_tests.append(f)

        return len(failed_tests) == 0, failed_tests

