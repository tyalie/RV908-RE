from enum import EnumMeta, Enum

class BytesEnumMeta(EnumMeta):
    def __contains__(cls, obj) -> bool:
        if isinstance(obj, bytes):
            return any(obj == v.value for v in EnumMeta.__iter__(cls))
        else:
            return super().__contains__(obj)

class BytesEnum(bytes, Enum, metaclass=BytesEnumMeta):
    ...
