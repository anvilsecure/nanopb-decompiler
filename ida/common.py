import collections
import io
import enum
import typing
import dataclasses

class DecompileError(Exception):
    pass

def message_name(ea : int):
    return "Message_{:X}".format(ea)

class RepeatRule(enum.IntEnum):
    REQURIED = 0x00
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