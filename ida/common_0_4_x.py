import enum
import typing
import ctypes
import struct

import ida_bytes
import ida_kernwin
import ida_segment

from common import *

class ScalarType(enum.IntEnum):
    BOOL = 0x00
    INT = 0x01
    UINT = 0x02
    SINT = 0x03
    FIXED32 = 0x04
    FIXED64 = 0x05

    LAST_PACKABLE = 0x05

    BYTES = 0x06
    STRING = 0x07
    SUBMESSAGE = 0x08
    SUBMESSAGE_CB = 0x09
    EXTENSION = 0x0a
    FIXED_LENGTH_BYTES = 0x0b

class FieldInfo045(FieldInfo[ScalarType]):

    @staticmethod
    def from_pb_field_info(info : typing.Any, extra : int):
        return FieldInfo(
            info.tag,
            ScalarType(info.type & 0b1111),
            RepeatRule((info.type >> 4) & 0b11),
            AllocationType((info.type >> 6) & 0b11),
            info.data_offset,
            info.size_offset,
            info.data_size,
            info.array_size,
            extra)
    
    @property
    def is_submessage(self):
        return self.field_type in (ScalarType.SUBMESSAGE, ScalarType.SUBMESSAGE_CB)



class FieldInfo_1(ctypes.Structure):
    _pack_ = True
    _fields_ = [
        ("len", ctypes.c_uint8, 2),
        ("tag", ctypes.c_uint8, 6),
        ("type", ctypes.c_uint8),
        ("data_offset", ctypes.c_uint8),
        ("size_offset", ctypes.c_uint8, 4),
        ("data_size", ctypes.c_uint8, 4),
    ]

    @property
    def array_size(self):
        return 0

class FieldTag_Mixin:

    @property
    def tag(self):
        return (self.tag_u << 6) | (self.tag_l)

class FieldInfo_2(ctypes.Structure, FieldTag_Mixin):
    _pack_ = True
    _fields_ = [
        ("len", ctypes.c_uint8, 2),
        ("tag_l", ctypes.c_uint8, 6),
        ("type", ctypes.c_uint8),
        ("array_size", ctypes.c_uint16, 12),
        ("size_offset", ctypes.c_uint8, 4),
        ("data_offset", ctypes.c_uint16),
        ("data_size", ctypes.c_uint16, 12),
        ("tag_u", ctypes.c_uint16, 4),
    ]

class FieldInfo_4(ctypes.Structure, FieldTag_Mixin):
    _pack_ = True
    _fields_ = [
        ("len", ctypes.c_uint8, 2),
        ("tag_l", ctypes.c_uint8, 6),
        ("type", ctypes.c_uint8),
        ("array_size", ctypes.c_uint16),
        ("size_offset", ctypes.c_uint32, 8),
        ("tag_u", ctypes.c_uint32, 24),
        ("data_offset", ctypes.c_uint32),
        ("data_size", ctypes.c_uint32),
    ]

class FieldInfo_8(ctypes.Structure, FieldTag_Mixin):
    _pack_ = True
    _fields_ = [
        ("len", ctypes.c_uint8, 2),
        ("tag_l", ctypes.c_uint8, 6),
        ("type", ctypes.c_uint8),
        ("reserved1", ctypes.c_uint16),
        ("size_offset", ctypes.c_uint32, 8),
        ("tag_u", ctypes.c_uint32, 24),
        ("data_offset", ctypes.c_uint32),
        ("data_size", ctypes.c_uint32),
        ("array_size", ctypes.c_uint32),
        ("reserved2", ctypes.c_uint32),
        ("reserved3", ctypes.c_uint32),
        ("reserved4", ctypes.c_uint32),
    ]

class Decompiler04x(Decompiler):

    def __init__(self, field_size, is_64bit : int):
        super().__init__(field_size)
        if is_64bit:
            self.read_ptr_func = ida_bytes.get_64bit
            self.ptr_fmt = "Q"
            self.ptr_size = 8
        else:
            self.read_ptr_func = ida_bytes.get_32bit
            self.ptr_fmt = "I"
            self.ptr_size = 4
    
    def parse_pb_field(self, ea : int):
        size = ida_bytes.get_byte(ea) & 0b11

        if size == 0:
            pb_field = FieldInfo_1.from_buffer_copy(ida_bytes.get_bytes(ea, 1 * 4))
        elif size == 1:
            pb_field = FieldInfo_2.from_buffer_copy(ida_bytes.get_bytes(ea, 2 * 4))
        elif size == 2:
            pb_field = FieldInfo_4.from_buffer_copy(ida_bytes.get_bytes(ea, 4 * 4))
        else:
            pb_field = FieldInfo_8.from_buffer_copy(ida_bytes.get_bytes(ea, 4 * 8))
        
        return pb_field
    
    def parse_msgdesc_s(self, ea : int) -> tuple[int, int, int]:
        raise NotImplemented()

    def parse_message(self, ea : int):
        field_info_ptr, submsg_info_ptr, default_value_ptr = self.parse_msgdesc_s(ea)

        # first we are going to read in the defaults... They are stored in wire format as a PB stream
        defaults = dict[int,PBField]()
        if default_value_ptr != None and default_value_ptr != 0:
            defaults_decoder = PBDecoder(default_value_ptr)
            for field in defaults_decoder.parse():
                defaults[field.field_number] = field
        print(defaults)
        
        fields = []

        while True:
            pb_field = self.parse_pb_field(field_info_ptr)
            if pb_field.tag == 0:
                # indicates the end of the array
                break

            field_type = ScalarType(pb_field.type & 0x0f)
            if field_type in (ScalarType.SUBMESSAGE, ScalarType.SUBMESSAGE_CB):
                extra = self.read_ptr_func(submsg_info_ptr)
                submsg_info_ptr += self.ptr_size
            else:
                # Lets lookup a default
                extra = None
                if pb_field.tag in defaults:
                    default = defaults[pb_field.tag]
                    if field_type == ScalarType.STRING:
                        extra = default.str
                    elif field_type == ScalarType.SINT:
                        extra = default.sint
                    elif field_type == ScalarType.BOOL:
                        extra = default.bool
                    elif field_type == ScalarType.INT:
                        if pb_field.data_size == 4:
                            extra = default.int32
                        else:
                            extra = default.int64
                    else:
                        extra = default.data
                
            field = FieldInfo045.from_pb_field_info(pb_field, extra)

            print(field)

            fields.append(field)
            field_info_ptr += ctypes.sizeof(pb_field)
        
        return fields
    
    def group_fields(self, fields: list[FieldInfo]) -> tuple[list[FieldInfo], list[FieldInfo]]:
        result = []
        oneof_fields = dict[int,list[FieldInfo]]()

        for field in fields:
            if field.repeat_rules == RepeatRule.ONEOF:
                oneof = oneof_fields.get(field.data_offset, None)
                if oneof == None:
                    oneof = []
                    oneof_fields[field.data_offset] = oneof
                    result.append(oneof)
                
                oneof.append(field)
            else:
                result.append(field)
        
        return result


def run_decompiler(decompiler_class):
    ea = ida_kernwin.get_screen_ea()
    seg = ida_segment.getseg(ea)
    if seg != None:
        field_size = ida_kernwin.ask_long(16, "Field Size (16, 32)")
        if field_size in (16, 32):
            decompiler = decompiler_class(field_size, seg.is_64bit())
            decompiler.add_message(ea)
            print(decompiler.to_proto())
        else:
            print("Invalid field size:", field_size)
    else:
        print("Cursor not in a segment")

