from ctypes.wintypes import SC_HANDLE
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
    FIXED32 = 0x03
    FIXED64 = 0x04
    BYTES = 0x05
    STRING = 0x06
    SUBMESSAGE = 0x07
    EXTENSION = 0x08
    FIXED_LENGTH_BYTES = 0x09

class Decompiler030(Decompiler):

    def __init__(self, field_size : int, is_64bit : int):
        super().__init__(field_size)

        if field_size == 8:
            size_fmt = "B"
            self.ida_get_field_bits = ida_bytes.get_byte
        elif field_size == 16:
            size_fmt = "H"
            self.ida_get_field_bits = ida_bytes.get_16bit
        else:
            size_fmt = "I"
            self.ida_get_field_bits = ida_bytes.get_32bit

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
            
            field_type = ScalarType(field_type & 0b1111)

            if extra == 0:
                extra = None
            else:
                if field_type == ScalarType.FIXED32:
                    extra = ida_bytes.get_32bit(extra)
                elif field_type == ScalarType.FIXED64:
                    extra = ida_bytes.get_64bit(extra)
                elif field_type in (ScalarType.INT, ScalarType.UINT, ScalarType.SINT):
                    if data_size == 1:
                        extra = ida_bytes.get_byte(extra)
                        sign_mask = (1 << 7)
                    elif data_size == 2:
                        extra = ida_bytes.get_16bit(extra)
                        sign_mask = (1 << 15)
                    elif data_size == 4:
                        extra = ida_bytes.get_32bit(extra)
                        sign_mask = (1 << 31)
                    else:
                        extra = ida_bytes.get_64bit(extra)
                        sign_mask = (1 << 63)
                    if field_type != ScalarType.UINT:
                        if extra & sign_mask:
                            extra = -1 * (((~extra) & (sign_mask - 1)) + 1)
                elif field_type == ScalarType.FIXED_LENGTH_BYTES:
                    extra = ida_bytes.get_bytes(extra, data_size)
                elif field_type == ScalarType.BYTES:
                    tmp = self.ida_get_field_bits(extra)
                    extra = ida_bytes.get_bytes(extra + self.field_size_bytes, tmp)
                elif field_type == ScalarType.STRING:
                    s = ""
                    while len(s) < data_size:
                        tmp = ida_bytes.get_byte(extra)
                        if tmp == 0x00:
                            break
                        s += chr(tmp)
                        extra += 1
                    extra = s
                        

            field = FieldInfo(
                tag,
                field_type,
                RepeatRule((field_type >> 4) & 0b11),
                AllocationType((field_type >> 6) & 0b11),
                data_offset, size_offset, data_size, array_size, extra)
            
            print(field)

            fields.append(field)
            ea += self.pb_field_size
        
        return fields

    def group_fields(self, fields: list[FieldInfo]) -> list[FieldInfo | list[FieldInfo]]:
        result = []
        oneof_fields = typing.OrderedDict[int,list[FieldInfo]]()
        last_offset = None

        for field in fields:
            if field.repeat_rules == RepeatRule.ONEOF:
                offset = field.data_offset
                if offset == self.max_value:
                    if last_offset == None:
                        raise DecompileError("Missing the starting field for a oneof group...")
                    offset = last_offset

                oneof = oneof_fields.get(offset, None)
                if oneof == None:
                    oneof = []
                    oneof_fields[offset] = oneof
                    result.append(oneof)
                
                oneof.append(field)
                last_offset = offset
            else:
                result.append(field)
        
        return result

ea = ida_kernwin.get_screen_ea()
seg = ida_segment.getseg(ea)
if seg != None:
    field_size = ida_kernwin.ask_long(8, "Field Size (8, 16, 32)")
    if field_size in (8, 16, 32):
        decompiler = Decompiler030(field_size, seg.is_64bit())
        decompiler.add_message(ea)
        print(decompiler.to_proto())
    else:
        print("Invalid field size:", field_size)
else:
    print("Cursor not in a segment")

