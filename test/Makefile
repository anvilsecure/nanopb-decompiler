NANOPB_DIR = nanopb

# Compiler flags to enable all warnings & debug info
CFLAGS = -Wall -Werror -g -O0
CFLAGS += "-I$(NANOPB_DIR)"

# C source code files that are required
CSRC  = sample.c                   # The main program
CSRC += sample.pb.c                # The compiled protocol definition
CSRC += $(NANOPB_DIR)/pb_encode.c  # The nanopb encoder
CSRC += $(NANOPB_DIR)/pb_decode.c  # The nanopb decoder
CSRC += $(NANOPB_DIR)/pb_common.c  # The nanopb common parts

# Build rule for the main program
sample: $(CSRC)
	$(CC) $(CFLAGS) -osample $(CSRC)

clean:
	rm -rf sample sample.dSYM sample.i64

reset:
	rm -rf sample sample.dSYM sample.i64 sample.pb sample.pb.c sample.pb.h
