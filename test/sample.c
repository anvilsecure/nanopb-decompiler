#include <stdio.h>
#include <pb_encode.h>
#include <pb_decode.h>
#include "sample.pb.h"

int main()
{
    /* This is the buffer where we will store our message. */
    uint8_t buffer[1024];
    size_t message_length;
    bool status;
    
    /* Encode our message */
    {
        MyMessage message = MyMessage_init_zero;
        
        /* Create a stream that will write to our buffer. */
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        
        /* Fill in some values */
        message.uid = 13;
        
        /* Now we are ready to encode the message! */
        status = pb_encode(&stream, MyMessage_fields, &message);
        message_length = stream.bytes_written;
        
        /* Then just check for any errors.. */
        if (!status)
        {
            printf("Encoding failed: %s\n", PB_GET_ERROR(&stream));
            return 1;
        }
    }
    
    /* Decode the message */
    {
        /* Allocate space for the decoded message. */
        MyMessage message = MyMessage_init_zero;
        
        /* Create a stream that reads from the buffer. */
        pb_istream_t stream = pb_istream_from_buffer(buffer, message_length);
        
        /* Now we are ready to decode the message. */
        status = pb_decode(&stream, MyMessage_fields, &message);
        
        /* Check for errors... */
        if (!status)
        {
            printf("Decoding failed: %s\n", PB_GET_ERROR(&stream));
            return 1;
        }
    }
    
    return 0;
}