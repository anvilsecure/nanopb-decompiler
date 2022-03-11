import enum

from common_0_3_x import *

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

run_decompiler(ScalarType)
