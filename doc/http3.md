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

Reassembly of the QUIC stream comprises several actions. Consider the following 
transmission:

1. STREAM frame 0 carries a single fragment of PDU 0. 
2. STREAM frame 1 carries 3 PDU fragments:
   1. The last fragment of PDU 0
   2. The sole fragment of PDU 1
   3. The first fragment of PDU 2
3. STREAM frame 2 carries the last fragment of PDU 2.   

```
+------------------------+----------------------------------------+--------------------+
|STREAM frame: 0         |STREAM frame: 1                         |STREAM frame: 2     |
|Length: 1506            |Length: 1506                            |Length: 1206        |
|                        |                                        |                    |
+---+--------------------+---+------------------------------------+---+----------------+
|Hdr|Payload             |Hdr|Payload                             |Hdr|Payload         |
+---+--------------------+---+-----------+------------+-----------+---+----------------+
    |                    |   |           |            |           |   |                |
    |frag 0_0            |   |frag 0_1   |frag 1_0    |frag 2_0   |   |frag 2_1        |
    |length: 1500        |   |length: 500|length: 200 |length: 800|   |length: 1200    |
    |                    |   |           |            |           |   |                |
    +--------------------+   +-----------+------------+-----------+   +----------------+
                                                                                        
                                                                                        
    +-----------------------------------+------------+---------------------------------+
    |PDU:    0                          |PDU:    1   |PDU:    2                        |
    |offset: 0                          |offset: 2000|offset: 2200                     |
    |length: 2000                       |length: 200 |length: 2000                     |
    |                                   |            |                                 |
    +-----------------------------------+------------+---------------------------------+

```

The reassembly requires: 
  1. Identifying the fragment boundaries. 
  2. Matching fragments to the corresponding PDUs.
  3. Concatenating the bytes from the fragments into contiguous tvbs, for the
     subdissector

The QUIC dissector lacks the knowledge on the PDU structure. Because of that it
has to depend on the sub-protocol dissector (HTTP3 in this case) to identify
the boundaries of the PDUs. 

The way Wireshark is commonly achieving such cooperation is by using two fields
in the `Packet Info` structure, which is visible to both the QUIC and the HTTP3
(or other subprotocol) dissectors. These two fields - `desegment_offset` and
`desegment_length` allow the higher-level protocol to request desegmentation of
a specific PDU, in a way similar to:

```
QUIC dissector {
    pinfo->desegment_length <- 0;
    invoke sub-protocol dissector;
    if (pinfo->desegment_length > 0) { 
        // Sub-protocol has requested desegmentation from `pinfo->desegment_offset` 
        // until `pinfo->desegment_offset + pinfo->desegment_length`
    }
}
```

Information on the individual fragmented PDUs is stored in the "Multi-Segment
PDU" data structure (commonly abbreviated as MSP).


The above is achieved with the following parsing loop:

```
DesegmentTvbuf:

Input:
   Tvb - data of the current QUIC segment
   Offset - offset within the Tvb
   Length  - length of the Tvb
   Stream  - current state of the stream 
   Pinfo   - packet info, which is used by the subdissector to inform of the fragmentation.
 
Setup:

// Move from the tvb-based offsets to the stream-based offsets
Seq    <- Stream->stream_offset // set Seq to the logical offset in the stream 
Nxtseq <- Seq + Length - Offset  // set Nxtseq to the logical ofset of the next TVB


Msp               <- Null  // Multi-segment PDU contains the segmentation metadata
ReassembledChain  <- Null  // ReassembledChain contains the PDU.

While Seq < Nxtseq: 

    // Find a segment chain we can pass to the sub-dissector
    ReassembleSegmentChain(Tvb, Msp, Seq, NxtSeq, Stream, Pinfo, ReassembledChain)

    If ReassembledChain != Null: 
        // SegmentChain contains the concatenation of segments that
        // contains the PDU. Unless the PDU ends on the segment boundary,
        // the SegmentChain will contain fragments of subsequent PDUs.
        // It can also contain one or several unfragmented PDUs, 
        // followed by a fragment.

        InvokeSubDissector(CompositeTvb, Pinfo)


        // The sub-dissector will attempt to dissect as many PDUs as it can.
        // There are several possible outcomes:

        If Pinfo->desegment_length == 0:
            // The sub-dissector has successfully dissected the PDU (plus possible extra PDUs)
            // and has stopped at a PDU boundary. In this case, `Pinfo->desegment_length` will 
            // be equal to zero.
            // We are done with this Tvb.
            Return 

        Else: 
            // More desegmentation is needed 
            Seq <- Pinfo->desegment_offset

            If Pinfo->desegment_offset != Msp->seq:
                // The sub-dissector has sucessfully dissected the PDU associated with
                // Msp (along with any unfragmented PDUs that may follow), and had stopped
                // at a fragment of some future PDU. 
            
                Msp <- CreateNewMsp(Pinfo->desegment_offset, Pinfo->desegment_length)
                
            Else:
                // The sub-dissector was not able to successfully dissect the PDU. One possible
                // scenario is that the sub-dissector was not able to accurately establish the 
                // PDU boundaries, and had to request the entire segment. 
                Msp <- UpdateMsp(Msp, Pinfo->desegment_length)

            // In both cases more data has to be consumed from the Tvb.
            Continue
```

The `ReassembleSegmentChain` function encapsulates the MSP feeding:


```
ReassembleSegmentChain:

Input:
   Tvb     - data of the current QUIC segment
   Msp     - Current MSP 
   Seq     - current position in the stream 
   Nxtseq  - position of the next segment in the stream
   Stream  - current state of the stream 
   Pinfo   - packet info, which is used by the subdissector to inform of the fragmentation.

Output:
    ReassembledChain <- Null 
    OutMsp           <- Null 
    OutSeq           <- Seq
 

If Msp == Null:
    // The MSP may have been set by a previous iteration of
    // the desegmentation loop. In this case proceed feeding
    // it with data. Otherwise, attempt to determine whether Seq belongs to a fragmented MSP
    Msp <- LookupCorrespondingMsp(Stream, Seq, Nxtseq)

    if Msp == Null:
        // We could not find a MSP that this segment corresponds to. Assume
        // that a PDU starts on the first byte of the segment
        ReassembledChain <- Tvb 
        OutMsp <- Null
        OutSeq <- Seq 
        Return 

Invariant: Msp != Null 

If IsRetransmission(Msp, Seq, Nxtseq):
    // Some bytes between Seq and Nxtseq have already been seen
    // Advance the Seq to the first unseen point.
    ReassembledChain <- Null 
    OutMsp <- Msp 
    OutSeq <- Min(Msp->NxtSeq, NxtSeq)
    Return 

// We have found MSP and it is not a retransmission. Feed me, Seymour! 
OutSeq <- AddDataToMsp(Msp, Tvb, Seq, NxtSeq)
OutMsp <- Msp

If IsCompletelyDefragmented(Msp):
    // We belive that Msp has been completely defragmented
    ReassembledChain <- ConcatReassembledChain(Msp)

Return
```     


#### Testing the QUIC stream reassembly

To test for correct reassembly we can use the following fields:
- `quic.fragments`, which marks that a reassembly has been completed
- `quic.fragment.count`, which reports the number of fragments that have been reassembled
- `quic.reassembled.length`, which shows the size of the reassembled PDU.

Note that the two last fields should only be set when the reassembly has happened. This allows running the following tests:

1. `quic.fragments => quic.fragment.count > 1` - more than one fragment required for reassembly
2. `quic.fragments => quic.reassembled.length > 1` - if the segment has reassembled data, the reassembled PDU must have non-zero length

In addition, the following filters should produce zero results:
1. `not quic.fragments && quic.fragment.count > 0`
2. `not quic.fragments && quic.reassembled.length > 0`

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

# Dissecting HTTP3


## Fields to expose

"http3.qpack" pertains to the session-level QPACK data (sizes of the dynamic tables).
"http3.stream.qpack" pertains to the stream-level QPACK data (sizes of the dynamic tables).
"http3.stream.qpack.blocked"

## Using QPACK to decode HEADER frames

### Managing the QPACK state

The dissector needs to maintain the QPACK state of both the client and the
server throughout the entire H3 session. That requires keeping the state of the
H3 session in between the calls to `dissect_http3` in a `http3_session_t`:

```
typedef struct {
    nghttp3_qpack_decoder *decoders[2]; // for requests/responses
} http3_session_t;
```

The `http3_session_t` instances are stored as `conversation_protocol_data`. The
`conversations` are located either by the QUIC connection ids, if found, or by
5-tuple if absent.

In addition to the per-session state, `nghttp3` requires storing per-stream
context in `nghttp3_qpack_stream_context`.

Both the session level data and the stream level data are deallocated via
callbacks in the file scope.

Open questions:
1. Large files can have a lot of sessions/conversations, can use a lot of
   memory. Maybe worth adding a setting to disable the QPACK decoding.

### Updating QPACK decoders with QPACK Encoder data

When the dissector processes PDUs from a QPACK Encoder stream, it gets the
associated `http3_session_t` and selects the right decoder from the `decoders`
pair. Then the dissector passes the PDU data to the correct dissector.

### Decompressing HTTTP3 headers

When processing a QPACK encoded HEADERS frame, the dissector gets both the `http3_session_t` and `http3_stream_t` instances associated with the stream, and starts the decoding loop:


```
nghttp3_qpack_decoder *decoder = h3_session->decoders[from_server];
nghttp3_qpack_stream_context *sctx = h3_stream->qpack_context;
nghttp3_qpack_nv header;
uint8_t decode_status = 0;
uint8_t error = 0;
while (has_more_data) {
    error = nghttp3_qpack_decoder_read_request(
            decoder, sctx, &header, &decode_status, pdu_data, pdu_data_len, fin);
    if (error) {
        // add expert info
        break;
    }
    if (decode_status & DECODE_BLOCKED) {
        // add expert info
        break;
    }
    if (decode_status & EMIT) {
        // header contains the name-value pair
        // add to the headers dissection tree.
    }
    if (decode_status & FINAL) {
        // all the header data has been decoded
        // append the remaining data to the headers dissection tree.
    }
} // decoding loop
```

Open questions:
1. Where to store the header data that could not be decoded due to QPACK
   insertion count?  Initially, just indicate that it is blocked and append the
   hex data to the headers dissection tree.
2. What happnes if after the decoding has finished successfully, the HEADERS
   frame contains more data?
