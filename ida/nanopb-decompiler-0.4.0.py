import struct

import ida_bytes

from common_0_4_x import Decompiler04x, run_decompiler

class Decompiler043(Decompiler04x):
    
    def parse_msgdesc_s(self, ea : int):
        field_fmt = "H" if self.field_size == 16 else "I"
        fmt = f"<{field_fmt}{self.ptr_fmt*3}"
        return struct.unpack(fmt, ida_bytes.get_bytes(ea, struct.calcsize(fmt)))[1:]


run_decompiler(Decompiler043)
