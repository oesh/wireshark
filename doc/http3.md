# Design notes on the HTTP3 dissector for wireshark 



# Goals 

1. Adding ability to analyze HTTP3 headers with Wireshark.
2. Adding ability to analyze all frames except for the HTTP DATA frames.
3. Adding abilitty to analyze the HTTP3 DATA frames.

# Timeline 

The work is being sponsored by Facebook and therefore needs to meet the internal timelines/needs of FB. 

## Goal 1 timeline 

I have been given 10 days worth of work in July/early August to work on:

1. QUIC stream reassembly.
2. HTTP3 stream reassembly.
3. HTTP3 frame header disseciton.
4. HTTP3 QPACK state management (via 3rd party lib, e.g. nghttp3)
5. HTTP3 HEADER dissection.


## Goal 2 timeline 

Possibly in the second half of 2020, no specific time allocated.

1. SETTINGS frame
3. PUSH PROMISE / MAX PUSH ID / CANCEL PUSH frames

## Goal 3 timeline 

Possibly in the second half of 2020, no specific time allocated.

1. Solving the memory considerations for the large PDUs.
2. Solving the question of sub-dissectors for the HTTP3 payloads.

# Design considerations 

## High level control flow

```
       +------------------+                                              
       |  dissect_http3   |                                              
       +------------------+                                              
                 |                                                       
                 |                                                       
                 v                                                       
         +---------------+                                               
         |dissect_stream |                                               
         +---------------+                                               
                 |                                                       
                 |      +------------------------+                       
                 +----->| dissect_control_stream |--+                    
                 |      +------------------------+  |                    
                 |      +------------------------+  |                    
                 +----->|  dissect_data_stream   |--+                    
                 |      +------------------------+  |                    
                 |                                  v                    
                 |                         +----------------+            
                 |                         | dissect_frame  |            
                 |                         +----------------+            
                 |                                  |                    
                 |                                  |  +----------------+
                 |                                  +->|  dissect_data  |
                 |                                  |  +----------------+
                 |                                  |  +----------------+
                 |                                  +->| dissect_other  |
                 |                                  |  +----------------+
                 |   +--------------------+         |  +----------------+
                 +-->|dissect_qpack_stream|         +->|dissect_headers |
                     +--------------------+            +----------------+
                                |                               |        
                                |                               |        
                                |       +---------------+       |        
                                |       |     QPACK     |       |        
                                +------>|  dictionary   |<------+        
                                        +---------------+                
```


## QUIC/HTTP3 reassembly 

The QUIC and the HTTP3 dissectors work together to reassemble HTTP3 data:

### QUIC stream reassembly

The QUIC dissector reads QUIC stream data, and performs the following parsing loop:

```
While stream data availalbe:
  MSP <- find pending PDU that overlaps with the available data.
  If MSP:
     Attempt to reassemble the MSP
     If MSP is fully reassembled:
         IsFragmented <- Invoke HTTP3 dissector
         Check invariant: !IsFragmented
     Else:
         Append a copy of stream data bytes to the MSP.
         Return.
  Else:
    IsFragmented <- Invoke HTTP3 dissector.
    If IsFragmented:
       MSP <- Create new MSP
       Append a copy of stream data bytes to the MSP
       Return.
    Else:
       Continue to execute the reading loop.
```


### HTTP3 data reassembly 

The QUIC dissector invokes the HTTP3 parser in two situations:

1. When a fragmetned PDU becomes fully ressembled. In this case the HTTP3 dissector has enough data. 
2. When a new PDU begins. In this case the HTTP3 dissector may not have enough data. 

In the latter case, the HTTP3 parser indicates that more data is needed by
setting the `desegment_offset` and `desegment_len` fields in the `protocol
info` shared structure.

This will cause the QUIC parser to start reassembling the data for the PDU,
until it becomes fully reassembled.

### Skipping data - potential memory optimization

Initially, the HTTP3 dissector will focus on the HTTP headers. Because of that,
it is possible to optimize the memory use by indicating that the HTTP3 parser
is not interested in the actual desegmented data, but only in the next PDU.
This can be done by adding a flag to the `protocol info` structure.
