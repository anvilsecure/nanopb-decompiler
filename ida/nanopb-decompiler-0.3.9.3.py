import enum
import typing
import struct
import io
import collections

import ida_bytes
import ida_kernwin


def message_name(ea : int):
    return "Message_{:X}".format(ea)

class ScalarType(enum.IntEnum):
    INT = 0x00
    UINT = 0x01
    SINT = 0x02
    FLOAT = 0x03
    DOUBLE = 0x04

    LAST_PACKABLE = 0x04

    BYTES = 0x05
    STRING = 0x06
    SUBMESSAGE = 0x07
    EXTENSION = 0x08
    FIXED_LENGTH_BYTES = 0x09

class RepeatRule(enum.IntEnum):
    REQURIED = 0x00
    OPTIONAL = 0x01
    REPEATED = 0x02
    ONEOF = 0x03

class AllocationType(enum.IntEnum):
    STATIC = 0x00
    POINTER = 0x01
    CALLBACK = 0x02

class PBField(typing.NamedTuple):
    tag : int
    field_type : ScalarType
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
    def is_concrete_type(self):
        return self.field_type not in (ScalarType.LAST_PACKABLE, ScalarType.EXTENSION)
    
    @property
    def type_name(self):
        if self.field_type == ScalarType.SUBMESSAGE:
            return message_name(self.extra)
        elif self.field_type == ScalarType.FIXED_LENGTH_BYTES:
            return "bytes"
        elif self.field_type in (ScalarType.INT, ScalarType.UINT, ScalarType.SINT):
            # we only have bool or [int,uint,sint][32,64]
            num_bits = self.data_size * 8
            if num_bits == 8:
                return "bool"
            return f"{self.field_type.name.lower()}{num_bits}"
        else:
            return self.field_type.name.lower()

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

    def __init__(self, field_size):
        self.messages = typing.OrderedDict[int,typing.List[PBField]]()

        self.field_size = field_size
        self.max_value = (2 ** field_size) - 1
        if field_size == 8:
            size_fmt = "B"
        elif field_size == 16:
            size_fmt = "H"
        else:
            size_fmt = "I"
        
        self.pb_field_fmt = f"<{size_fmt}B{size_fmt}{size_fmt.lower()}{size_fmt}{size_fmt}I"
        
        self.pb_field_size = struct.calcsize(self.pb_field_fmt)
    
    def parse_message(self, ea : int):
        fields = []

        while True:
            data = ida_bytes.get_bytes(ea, self.pb_field_size)

            tag, field_type, data_offset, size_offset, data_size, array_size, extra = struct.unpack(self.pb_field_fmt, data)
            if tag == 0:
                # indicates the end of the array
                break

            field = PBField(
                tag,
                ScalarType(field_type & 0b1111),
                RepeatRule((field_type >> 4) & 0b11),
                AllocationType((field_type >> 6) & 0b11),
                data_offset, size_offset, data_size, array_size, extra)
            
            print(field)

            fields.append(field)
            ea += self.pb_field_size
        
        return fields

    def add_message(self, ea : int):
        if ea not in self.messages:
            fields = self.parse_message(ea)
            self.messages[ea] = fields

            for field in fields:
                if field.field_type == ScalarType.SUBMESSAGE:
                    self.add_message(field.extra)
    
    def to_proto(self):
        output = Outputer()

        output.print("// Decompiled nanopb protobuf")
        output.print()
        output.print("syntax = \"proto2\";")
        output.print()
        output.print('import "nanopb.proto"; // include from the nanopb project, can remove if there are no options')
        output.print()


        def output_message(ea, fields):
            counts = Counters()
            in_one_of = False

            output.print(f"message {message_name(ea)} {{")
            output.inc_level()
            for field in fields:
                if field.repeat_rules == RepeatRule.ONEOF:
                    if field.data_offset != self.max_value:
                        # this is the first element of a oneof/union
                        if in_one_of:
                            # was already in one... so close it
                            output.close_level()

                        # start a new oneof
                        output.print(f"oneof union_{counts.oneof} {{")
                        output.inc_level()
                        in_one_of = True
                else:
                    if in_one_of:
                        # on to something else, close the oneof
                        output.close_level()
                        in_one_of = False

                if field.is_concrete_type:
                    tokens = []

                    if field.repeat_rules != RepeatRule.ONEOF:
                        tokens.append(field.label)
                    
                    tokens.append(field.type_name)
                    tokens.append(f"field_{counts.field}")
                    tokens.append("=")
                    tokens.append(f"{field.tag}")

                    options = []

                    if field.field_type in (ScalarType.STRING, ScalarType.BYTES) and field.allocation_type == AllocationType.STATIC or \
                            field.field_type == ScalarType.FIXED_LENGTH_BYTES:
                        # if we are a static type of string/bytes or a field length bytes we will have a max size
                        options.append(f"(nanopb).max_size = {field.data_size}")

                        if field.field_type == ScalarType.FIXED_LENGTH_BYTES:
                            options.append("(nanopb).fixed_length = true")
                    
                    if field.repeat_rules == RepeatRule.REPEATED:
                        options.append(f"(nanopb).max_count = {field.array_size}")
                    
                    if len(options) > 0:
                        tokens.append(f'[{", ".join(options)}]')

                    output.print(" ".join(tokens), end=";\n")
                else:
                    print("Unknown type to ouput:", field)

            if in_one_of:
                output.close_level()


            output.close_level()
    
        for ea, fields in self.messages.items():
            output_message(ea, fields)
            output.print()
                
        return str(output)


decompiler = Decompiler(16)

decompiler.add_message(ida_kernwin.get_screen_ea())

print(decompiler.to_proto())

