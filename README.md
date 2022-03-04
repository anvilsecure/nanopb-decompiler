# nanopb-decompiler

[nanopb](https://github.com/nanopb/nanopb) is a protobuf implementation focused on small size and is used on microcontrollers or other memory restricted systems. It has its own internal data structure, so tools made to reconstruct protobufs generated with the `protoc` tool do not work.

This IDAPython script will decompile the [nanopb](https://github.com/nanopb/nanopb) data structures from an executable and generate a protobuf definition. Some of the nanopb specific options, such as `max_size` and `fixed_length` are also recovered and annotated as options. Unfortunately the metadata contains no names, so Messages are named Message_ABCD where ABCD is the memory address where they were found, and fields are named sequentially.

```
syntax = "proto2";

import "nanopb.proto"; // include from the nanopb project

message Message_100008010 {
    requried uint32 field_1 = 1;
    requried uint32 field_2 = 2;
    requried uint32 field_3 = 3;
    oneof union_1 {
        Message_100007F10 field_4 = 4;
        Message_100007F30 field_5 = 5;
        Message_100007F80 field_6 = 6;
    }
}

message Message_100007F10 {
    requried int32 field_1 = 1;
}

message Message_100007F30 {
    requried bool field_1 = 1;
    optional string field_2 = 2 [(nanopb).max_size = 40];
    optional bytes field_3 = 3 [(nanopb).max_size = 32, (nanopb).fixed_length = true];
    requried bytes field_4 = 4;
}

message Message_100007F80 {
    requried float field_1 = 1;
}
```

## nanopb Versions

The internal `nanopb` data structures changes between versions0


## Usage

To use the script you need to:

1. First locate the memory location of the `nanopb` fields array. This will be an argument to `pb_decode` and the easiest way to find locate this function is to:
    1. Search IDA for the `wrong size for fixed count field` error string.
    2. Follow the XREF to the function that log this message. Depending on your `nanopb` version, this is either `pb_decode_noinit` or `pb_decode_inner`.
    3. Follow the XREF to the above function, which will be the `pb_decode` or `pb_decode_ex`. The 2nd argument will be the fields array.
2. Place the IDA curser on the start of the field array.
3. Run the script by File -> Script File... and selecting the `nanopb-decompiler-*.py` script that is correct for the `nanopb` your executable was built with.
4. Specify the field size, 8, 16, or 32 bit. The `nanopb` generator tries to save size will use either 8, 16, or 32 bits depending on the number of tags, and size of the messages. There is no metadata that specifies which size was used. You will have to look at the data and determine which size works best, or just try them all.