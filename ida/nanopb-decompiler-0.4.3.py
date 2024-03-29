import struct

import ida_bytes

from common_0_4_x import Decompiler04x, run_decompiler

class Decompiler043(Decompiler04x):
    
    def parse_msgdesc_s(self, ea : int):
        fmt = f"<{self.ptr_fmt*3}"
        return struct.unpack(fmt, ida_bytes.get_bytes(ea, struct.calcsize(fmt)))


run_decompiler(Decompiler043)
