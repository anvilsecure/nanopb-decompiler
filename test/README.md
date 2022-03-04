# Test Program

This is a test program with a sample protocol `sample.proto` with nanopb options `sample.options`. Used to try out different versions of nanopb and build an executable that can be easily reverse engineered with IDA pro and the decompiler script run on.

To build:

1. Generate the `sample.pb.c` and `sample.pb.h` files using the version of nanopb that is being tested. The process varies by version, so refer to the nanopb [documentation](https://github.com/nanopb/nanopb/tree/master/docs).
2. From the nanopb source directory copy `pb.h`, `pb_common.*`, `pb_decode.*`, and `pb_encode.*` files into a `nanopb` sub folder.
3. Run `make` to build the sample executable.
