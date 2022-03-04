import enum
import typing
import struct
import io
import collections

import ida_bytes
import ida_kernwin
import ida_segment

from common import *

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

class Decompiler0393(Decompiler):

    def __init__(self, field_size : int, is_64bit : int):
        super().__init__(field_size)

        if field_size == 8:
            size_fmt = "B"
        elif field_size == 16:
            size_fmt = "H"
        else:
            size_fmt = "I"

        if is_64bit:
            ptr_fmt = "Q"
        else:
            ptr_fmt = "I"
        
        self.pb_field_fmt = f"<{size_fmt}B{size_fmt}{size_fmt.lower()}{size_fmt}{size_fmt}{ptr_fmt}"
        self.pb_field_size = struct.calcsize(self.pb_field_fmt)

        print(self.pb_field_fmt, self.pb_field_size)
        print(ptr_fmt)
    
    def parse_message(self, ea : int):
        fields = []

        while True:
            data = ida_bytes.get_bytes(ea, self.pb_field_size)

            tag, field_type, data_offset, size_offset, data_size, array_size, extra = struct.unpack(self.pb_field_fmt, data)
            if tag == 0:
                # indicates the end of the array
                break

            field = FieldInfo(
                tag,
                ScalarType(field_type & 0b1111),
                RepeatRule((field_type >> 4) & 0b11),
                AllocationType((field_type >> 6) & 0b11),
                data_offset, size_offset, data_size, array_size, extra)
            
            print(field)

            fields.append(field)
            ea += self.pb_field_size
        
        return fields

ea = ida_kernwin.get_screen_ea()
seg = ida_segment.getseg(ea)
if seg != None:
    field_size = ida_kernwin.ask_long(8, "Field Size (8, 16, 32)")
    if field_size in (8, 16, 32):
        decompiler = Decompiler0393(field_size, seg.is_64bit())
        decompiler.add_message(ea)
        print(decompiler.to_proto())
    else:
        print("Invalid field size:", field_size)
else:
    print("Cursor not in a segment")

