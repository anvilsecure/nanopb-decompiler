import collections
import io
import enum
import typing
import dataclasses
import struct

import ida_bytes

class DecompileError(Exception):
    pass

def message_name(ea : int):
    return "Message_{:X}".format(ea)

class RepeatRule(enum.IntEnum):
    REQUIRED = 0x00
    OPTIONAL = 0x01
    SINGULAR = 0x01
    REPEATED = 0x02
    FIXARRAY = 0x02
    ONEOF = 0x03

class AllocationType(enum.IntEnum):
    STATIC = 0x00
    POINTER = 0x01
    CALLBACK = 0x02

# the type enums change based on the version, so making this generic and then we look
# up things based on the name of the enum
T = typing.TypeVar("T", bound=enum.IntEnum)
@dataclasses.dataclass
class FieldInfo(typing.Generic[T]):
    tag : int
    field_type : T
    repeat_rules : RepeatRule
    allocation_type : AllocationType
    data_offset : int
    size_offset : int
    data_size : int
    array_size : int
    extra : int

    @property
    def label(self):
        return self.repeat_rules.name.lower()
    
    @property
    def type_name(self):
        if self.is_submessage:
            return message_name(self.extra)
        elif self.field_type.name == "FIXED_LENGTH_BYTES":
            return "bytes"
        elif self.field_type.name in ("INT", "UINT", "SINT"):
            num_bits = self.data_size * 8
            return f"{self.field_type.name.lower()}{num_bits}"
        else:
            return self.field_type.name.lower()
    
    @property
    def is_concrete_type(self):
        return self.field_type.name not in ("LAST_PACKABLE", "EXTENSION")
    
    @property
    def is_submessage(self):
        return self.field_type.name == "SUBMESSAGE"
    
    @property
    def has_max_size(self):
        return (self.allocation_type == AllocationType.STATIC and self.field_type.name in ("STRING", "BYTES")) or self.is_fixed_length
    
    @property
    def is_fixed_length(self):
        return self.field_type.name == "FIXED_LENGTH_BYTES"
    
    @property
    def is_bytes(self):
        return self.field_type.name.endswith("BYTES")

class Counters:

    def __init__(self):
        self.counts = collections.Counter()
    
    def __getattr__(self, __name: str) -> int:
        self.counts[__name] += 1
        return self.counts[__name]
    
class Outputer:

    def __init__(self):
        self.level = 0
        self.out = io.StringIO()
    
    def inc_level(self):
        self.level += 1
    
    def dec_level(self):
        if self.level > 0:
            self.level -= 1
    
    def print(self, s : str = "", end : str = "\n"):
        self.out.write(" " * self.level * 4)
        self.out.write(s)
        self.out.write(end)
    
    def printf(self, s : str, *args, end : str = "\n"):
        self.print(s.format(*args), end=end)
    
    def close_level(self):
        self.dec_level()
        self.print("}")
    
    def __str__(self):
        return self.out.getvalue()

class Decompiler:

    def __init__(self, field_size : int):
        self.field_size = field_size
        self.field_size_bytes = field_size // 8
        self.max_value = (2**self.field_size) - 1
        self.messages = typing.OrderedDict[int,list[FieldInfo]]()
    
    def parse_message(self, ea : int):
        return []

    def add_message(self, ea : int):
        if ea not in self.messages:
            fields = self.parse_message(ea)
            self.messages[ea] = fields

            for field in fields:
                if field.is_submessage:
                    self.add_message(field.extra)
    
    def group_fields(self, fields : list[FieldInfo]) -> list[FieldInfo | list[FieldInfo]]:
        return []
    
    def to_proto(self):
        output = Outputer()

        output.print("// Decompiled nanopb protobuf")
        output.print()
        output.print("syntax = \"proto2\";")
        output.print()
        output.print('import "nanopb.proto"; // include from the nanopb project')
        output.print()


        def output_message(ea, fields):
            counts = Counters()
            in_one_of = False
            union_offset = None

            fields = self.group_fields(fields)


            output.print(f"message {message_name(ea)} {{")
            output.inc_level()


            def print_field(field : FieldInfo):
                tokens = []

                if field.repeat_rules != RepeatRule.ONEOF:
                    tokens.append(field.label)
                
                tokens.append(field.type_name)
                tokens.append(f"field_{counts.field}")
                tokens.append("=")
                tokens.append(f"{field.tag}")

                options = []

                # see if we have a default
                if field.extra != None and not field.is_submessage:
                    extra = field.extra
                    if isinstance(extra, str):
                        extra = extra.replace('"', '\\"')
                        extra = f'"{extra}"'
                    elif isinstance(extra, bytes):
                        extra = "".join(map(lambda x: "\\x{:02x}".format(x), extra))
                        extra = f'"{extra}"'
                    options.append(f"default={extra}")

                if field.has_max_size:
                    # if we are a static type of string/bytes or a field length bytes we will have a max size
                    if field.is_bytes and not field.is_fixed_length:
                        # subtract the size of the length field
                        size = field.data_size - self.field_size_bytes
                    else:
                        size = field.data_size
                    options.append(f"(nanopb).max_size = {size}")

                    if field.is_fixed_length:
                        options.append("(nanopb).fixed_length = true")
                
                if field.repeat_rules == RepeatRule.REPEATED:
                    options.append(f"(nanopb).max_count = {field.array_size}")
                
                if len(options) > 0:
                    tokens.append(f'[{", ".join(options)}]')

                output.print(" ".join(tokens), end=";\n")

            for field in fields:
                if isinstance(field, FieldInfo):
                    print_field(field)
                else:
                    output.print(f"oneof union_{counts.oneof} {{")
                    output.inc_level()
                    for oneof_field in field:
                        print_field(oneof_field)
                        
                    output.close_level()
                
            output.close_level()
    
        for ea, fields in self.messages.items():
            output_message(ea, fields)
            output.print()
                
        return str(output)

class PBDecodeError(Exception):
    pass

class PBWireType(enum.IntEnum):
    VARINT = 0
    FIXED64 = 1
    LENGTH_DELIMITED = 2
    START_GROUP = 3
    END_GROUP = 4
    FIXED32 = 5

@dataclasses.dataclass
class PBField:
    field_number : int
    wire_type : PBWireType
    data : int | bytes

    @property
    def bool(self):
        return bool(self.data)

    @property
    def int32(self):
        # negative numbers are stored with 64-bits
        data = self.data & 0xffffffff
        if data & (1 << 31):
            return -1 * (((~data) & 0xffffffff) + 1)
        else:
            return data
    
    @property
    def int64(self):
        if self.data & (1 << 63):
            return -1 * (((~self.data) & 0xffffffffffffffff) + 1)
        else:
            return self.data
    
    @property
    def sint(self):
        if self.data & 1:
            return (~self.data) >> 1
        else:
            return self.data >> 1

    @property
    def str(self):
        return str(self.data, "utf8", errors="replace")

class PBStream:

    def __init__(self, ea, size=None):
        self.ea = ea
        self.end = None if size == None else ea + size
    
    def _check(self, length : int):
        if self.end == None:
            return
        if self.ea + length > self.end:
            raise PBDecodeError("Not enough bytes")

    def next_byte(self):
        self._check(1)
        tmp = ida_bytes.get_byte(self.ea)
        self.ea += 1
        return tmp
    
    def next_bytes(self, count : int):
        self._check(count)
        tmp = ida_bytes.get_bytes(self.ea, count)
        self.ea += count
        return tmp
    
    def next_varint(self):
        value = 0
        bitpos = 0
        while True:
            tmp = self.next_byte()
            value |= (tmp & 0x7f) << bitpos
            if tmp & 0x80 == 0:
                break
            bitpos += 7
        return value
    
    def next_fixed32(self):
        return struct.unpack("<I", self.next_bytes(4))[0]
    
    def next_fixed64(self):
        return struct.unpack("<Q", self.next_bytes(8))[0]
    

class PBDecoder:

    def __init__(self, ea : int):
        self.stream = PBStream(ea)
    
    def parse(self):
        fields = []
        while True:
            tag = self.stream.next_varint()
            if tag == 0:
                break

            field_num = tag >> 3
            wire_type = PBWireType(tag & 0b111)

            if wire_type == PBWireType.VARINT:
                data = self.stream.next_varint()
            elif wire_type == PBWireType.FIXED32:
                data = self.stream.next_fixed32()
            elif wire_type == PBWireType.FIXED64:
                data = self.stream.next_fixed64()
            elif wire_type == PBWireType.LENGTH_DELIMITED:
                length = self.stream.next_varint()
                data = self.stream.next_bytes(length)
            else:
                raise PBDecodeError(f"Unhandled wiretype: {wire_type}")
            
            fields.append(PBField(field_num, wire_type, data))
        
        return fields

    
