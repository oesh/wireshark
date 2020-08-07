/* packet-HTTP3.c
 * Routines for HTTP/3 dissection
 * Copyright 2019, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * https://tools.ietf.org/html/draft-ietf-quic-http-23
 *
 * Depends on the QUIC dissector for providing a reassembled stream of data.
 */

#include <config.h>
#include <stdio.h>

#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/expert.h>

#include "packet-quic.h"
#include "wsutil/pint.h"

#include <epan/conversation.h>

#ifdef HAVE_NGHTTP3
#include <epan/uat.h>
#include <epan/decode_as.h>
#include <nghttp3/nghttp3.h>
#endif

void proto_reg_handoff_http3(void);
void proto_register_http3(void);

static int proto_http3 = -1;
static int hf_http3_stream_type = -1;
static int hf_http3_push_id = -1;
static int hf_http3_frame_type = -1;
static int hf_http3_frame_length = -1;
static int hf_http3_frame_payload = -1;

static int hf_http3_header = -1;
static int hf_http3_header_length = -1;
static int hf_http3_header_count = -1;
static int hf_http3_header_name_length = -1;
static int hf_http3_header_name = -1;
static int hf_http3_header_value_length = -1;
static int hf_http3_header_value = -1;

static expert_field ei_http3_unknown_stream_type = EI_INIT;
static expert_field ei_http3_qpack_failed = EI_INIT;
static expert_field ei_http3_qpack_enc_update = EI_INIT;
static expert_field ei_http3_header_failed = EI_INIT;
static expert_field ei_http3_header_nv = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_http3 = -1;
static gint ett_http3_headers = -1;

#ifdef HAVE_NGHTTP3
static char nghttp3_vprintf_arena[2048];
#endif

/**
 * Unidirectional stream types.
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#section-6.2
 * https://tools.ietf.org/html/draft-ietf-quic-qpack-16#section-4.2
 */
enum http3_stream_type {
    HTTP3_STREAM_TYPE_CONTROL,
    HTTP3_STREAM_TYPE_PUSH,
    HTTP3_STREAM_TYPE_QPACK_ENCODER,
    HTTP3_STREAM_TYPE_QPACK_DECODER,
};

/*
 * Unidirectional stream types (62-bit code space).
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#section-6.2
 */
static const val64_string http3_stream_types[] = {
    /* 0x00 - 0x3f Assigned via Standards Action or IESG Review policies. */
    { 0x00, "Control Stream" },
    { 0x01, "Push Stream" },
    { 0x02, "QPACK Encoder Stream" },
    { 0x03, "QPACK Decoder Stream" },
    /* 0x40 - 0x3fff Assigned via Specification Required policy */
    /* 0x4000 - 0x3FFFFFFFFFFFFFFF Private Use */
    { 0, NULL }
};

/*
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#section-7
 * 62-bit space.
 */
#define HTTP3_FRAME_TYPE_HEADERS 0x01
static const val64_string http3_frame_types[] = {
    /* 0x00 - 0x3f Assigned via Standards Action or IESG Review policies. */
    { 0x00, "DATA" },
    { HTTP3_FRAME_TYPE_HEADERS, "HEADERS" },
    { 0x02, "Reserved" },
    { 0x03, "CANCEL_PUSH" },
    { 0x04, "SETTINGS" },
    { 0x05, "PUSH_PROMISE" },
    { 0x06, "Reserved" },
    { 0x07, "GOAWAY" },
    { 0x08, "Reserved" },
    { 0x09, "Reserved" },
    { 0x0d, "MAX_PUSH_ID" },
    { 0x0e, "DUPLICATE_PUSH" }, /**< Has been removed in draft-ietf-quic-http-26. */
    /* 0x40 - 0x3fff Assigned via Specification Required policy */
    /* 0x4000 - 0x3FFFFFFFFFFFFFFF Private Use */
    { 0, NULL }
};

enum http3_stream_direction {
    UPSTREAM,   /**< Client to server */
    DOWNSTREAM, /**< Server to client */
};

typedef struct _http3_stream_info {
    guint64 uni_stream_type;
    guint64 broken_from_offset;     /**< Unrecognized stream starting at offset (if non-zero). */
#ifdef HAVE_NGHTTP3
    nghttp3_qpack_stream_context *sctx; /**< Stream context for QPACK decoding */
#endif
    enum http3_stream_direction dir;
} http3_stream_info;

typedef struct _http3_session {
#ifdef HAVE_NGHTTP3
    nghttp3_qpack_decoder *qpack_decoders[2]; /**< Decoders for outgoing/incoming QPACK streams. */
#endif
    int id;
} http3_session;

http3_session* get_http3_session(packet_info *pinfo);

#ifdef HAVE_NGHTTP3
const size_t qpack_max_dtable_size = 8096;
const size_t qpack_max_blocked = 10;
#endif

/* Decompressed header field */
typedef struct {
    /* encoded (compressed) length */
    size_t enc_len;
    size_t len;
    const char *data;
} http3_header_t;

/* Cached decompressed header data in one packet_info */
typedef struct {
    /* list of pointer to wmem_array_t, which is array of
       http2_header_t */
    wmem_array_t *headers;
} http3_header_data_t;

/**
 * Whether this is a reserved code point for Stream Type, Frame Type, Error
 * Code, etc.
 */
static inline gboolean
http3_is_reserved_code(guint64 stream_type)
{
    return (stream_type - 0x21) % 0x1f == 0;
}

static gboolean
try_get_quic_varint(tvbuff_t *tvb, int offset, guint64 *value, int *lenvar)
{
    if (tvb_reported_length_remaining(tvb, offset) == 0) {
        return FALSE;
    }
    gint len = 1 << (tvb_get_guint8(tvb, offset) >> 6);
    if (tvb_reported_length_remaining(tvb, offset) < len) {
        return FALSE;
    }
    *lenvar = len;
    if (value) {
        gint n = (gint)tvb_get_varint(tvb, offset, -1, value, ENC_VARINT_QUIC);
        DISSECTOR_ASSERT_CMPINT(n, ==, len);
    }
    return TRUE;
}

/** Returns the size of the whole HTTP/3 frame. */
static int
get_http3_frame_size(tvbuff_t *tvb, int offset)
{
    int type_size, length_size;
    guint64 frame_length;

    if (!try_get_quic_varint(tvb, offset, NULL, &type_size)) {
        return 0;
    }
    offset += type_size;

    if (!try_get_quic_varint(tvb, offset, &frame_length, &length_size)) {
        return 0;
    }

    guint64 frame_size = type_size + length_size + frame_length;
    if (frame_size > G_MAXINT32) {
        // We do not support such large frames.
        return 0;
    }
    return (int)frame_size;
}

static gboolean
http3_check_frame_size(tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    int frame_size = get_http3_frame_size(tvb, offset);
    int remaining = tvb_reported_length_remaining(tvb, offset);
    if (frame_size && frame_size <= remaining) {
        return TRUE;
    }

    pinfo->desegment_offset = offset;
    pinfo->desegment_len = frame_size ? (frame_size - remaining): DESEGMENT_ONE_MORE_SEGMENT;
    return FALSE;
}

#ifdef  HAVE_NGHTTP3
static http3_header_t* decode_nghttp3_header(nghttp3_qpack_nv *nv, size_t enc_len) { 
    http3_header_t *out = wmem_new0(wmem_file_scope(), http3_header_t);
    guint32 len;

    out->enc_len = enc_len;

    nghttp3_vec name_vec = nghttp3_rcbuf_get_buf(nv->name);
    nghttp3_vec value_vec = nghttp3_rcbuf_get_buf(nv->value);
   
    out->len = name_vec.len + value_vec.len + sizeof(guint32) * 2;

    /* Prepare buffer... with the following format
       name length (uint32)
       name (string)
       value length (uint32)
       value (string)
     */
    char* pstr = wmem_realloc(wmem_file_scope(), NULL, out->len);
    out->data = pstr;

    len = (guint32)name_vec.len;
    phton32(pstr, len);
    pstr += sizeof(guint32);
    memcpy(pstr, name_vec.base, name_vec.len);
    pstr += name_vec.len;

    len = (guint32)value_vec.len;
    phton32(pstr, len);
    pstr += sizeof(guint32);
    memcpy(pstr, value_vec.base, value_vec.len);

    // TODO: cache the pstr
    return out;
} 

static int
dissect_http3_headers(
        tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint64 length, http3_stream_info *h3_stream) {

    tvbuff_t *dec_headers_block_tvb = tvb_new_composite();

    int dec_headers_block_len = 0;
    guint dec_headers_block_count = 0;
    guint i;
    int hoffset = 0;
    int remaining;
    proto_item *header, *ti;
    http3_header_data_t *header_data;

    header_data = (http3_header_data_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_http3, 0);
    if (!header_data) {
        header_data = wmem_new0(wmem_file_scope(), http3_header_data_t);
        header_data->headers = wmem_array_sized_new(wmem_file_scope(), sizeof(http3_header_t), 16);

        p_add_proto_data(wmem_file_scope(), pinfo, proto_http3, 0, header_data);
    }

    if (!PINFO_FD_VISITED(pinfo)) {

        nghttp3_qpack_nv nv;

        http3_session *h3_session = get_http3_session(pinfo);
        nghttp3_qpack_stream_context *sctx = h3_stream->sctx;
        nghttp3_qpack_decoder *decoder = h3_session->qpack_decoders[h3_stream->dir];

        nghttp3_buf enc_headers_block;
        // Get a coalesced copy of the TVB payload into the nghttp3 buffer
        enc_headers_block.begin = tvb_memdup(wmem_file_scope(), tvb, offset, length);
        enc_headers_block.pos = enc_headers_block.begin;
        enc_headers_block.end = enc_headers_block.begin + length;
        enc_headers_block.last = enc_headers_block.end;

        while ((remaining = (int)nghttp3_buf_len(&enc_headers_block)) > 0) {

            uint8_t decoding_flags;
            nghttp3_ssize nread = nghttp3_qpack_decoder_read_request(
                    decoder, sctx, &nv, &decoding_flags, enc_headers_block.pos, remaining, 1);

            if (nread < 0) {
                proto_tree_add_expert_format(tree, pinfo, &ei_http3_header_failed, tvb, offset, remaining,
                        "Failed to decode HTTP header dir=%d off=%d rem=%d nread=%lu",
                        h3_stream->dir,
                        offset,
                        remaining,
                        nread);
                break;
            }

            if (decoding_flags & NGHTTP3_QPACK_DECODE_FLAG_BLOCKED) {
                proto_tree_add_expert_format(tree, pinfo, &ei_http3_header_failed, tvb, offset, remaining,
                        "HTTP3 stream is blocked on QPACK update. Header value is lost. dir=%d off=%d rem=%d nread=%lu",
                        h3_stream->dir,
                        offset,
                        remaining,
                        nread);

            }

            if (decoding_flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
                // Convert the decodec nv into a header block
                http3_header_t *hdr = decode_nghttp3_header(&nv, nread);
                wmem_array_append(header_data->headers, hdr, 1);
            }

            if (decoding_flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL) {
                break;
            }

            if (nread == 0) {
                break;
            }

            offset += nread;
            enc_headers_block.pos += nread;
        }
    }


    // Collect the individual decoded headers into individual TVBs,
    // and append to the `dec_headers_block_tvb` composite TVB.
    for(i = 0; i < wmem_array_get_count(header_data->headers); ++i) {
        tvbuff_t *dec_hdr_tvb;
        http3_header_t *dec_hdr = wmem_array_index(header_data->headers, i);

        dec_headers_block_len += dec_hdr->len;
        dec_headers_block_count ++;

        /* Now setup the tvb buffer to have the new data */
        dec_hdr_tvb = tvb_new_child_real_data(tvb, dec_hdr->data, (int)dec_hdr->len, (int)dec_hdr->len);
        tvb_composite_append(dec_headers_block_tvb, dec_hdr_tvb);
    }

    tvb_composite_finalize(dec_headers_block_tvb);
    add_new_data_source(pinfo, dec_headers_block_tvb, "Decompressed Headers Block");

    ti = proto_tree_add_uint(tree, hf_http3_header_length, dec_headers_block_tvb, hoffset, 1, dec_headers_block_len);
    proto_item_set_generated(ti);

    ti = proto_tree_add_uint(tree, hf_http3_header_count, dec_headers_block_tvb, hoffset, 1, dec_headers_block_count);
    proto_item_set_generated(ti);

    for(i = 0; i < dec_headers_block_count; ++i) { 
        http3_header_t *dec_hdr = wmem_array_index(header_data->headers, i);

        proto_tree *header_tree;
        guint32 header_name_length;
        guint32 header_value_length;
        const guint8 *header_name;
        const guint8 *header_value;

        /* Add Header subtree with description */
        header = proto_tree_add_item(tree, hf_http3_header, tvb, offset, (int)dec_hdr->len, ENC_NA);

        header_tree = proto_item_add_subtree(header, ett_http3_headers);

        /* Add the header name length */
        proto_tree_add_item_ret_uint(
            header_tree, hf_http3_header_name_length, dec_headers_block_tvb, hoffset,
            sizeof(guint32), ENC_BIG_ENDIAN, &header_name_length);
        hoffset += sizeof(guint32);

        /* Add the header name */
        proto_tree_add_item_ret_string(
            header_tree, hf_http3_header_name, dec_headers_block_tvb, hoffset,
            header_name_length, ENC_ASCII|ENC_NA, wmem_packet_scope(), &header_name);
        hoffset += header_name_length;

        /* Add the header value length */
        proto_tree_add_item_ret_uint(
            header_tree, hf_http3_header_value_length, dec_headers_block_tvb, hoffset,
            sizeof(guint32), ENC_BIG_ENDIAN, &header_value_length);
        hoffset += sizeof(guint32);

        /* Add the header name */
        proto_tree_add_item_ret_string(
            header_tree, hf_http3_header_value, dec_headers_block_tvb, hoffset,
            header_value_length, ENC_ASCII|ENC_NA, wmem_packet_scope(), &header_value);
        hoffset += header_value_length;
    }

    return offset;
}
#endif /* HAVE_NGHTTP3 */

static int
dissect_http3_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, http3_stream_info *h3_stream)
{
    guint64 frame_type, frame_length;
    int lenvar;
    proto_item *pi;

    pi = proto_tree_add_item_ret_varint(tree, hf_http3_frame_type, tvb, offset, -1, ENC_VARINT_QUIC, &frame_type, &lenvar);
    offset += lenvar;
    if (http3_is_reserved_code(frame_type)) {
        proto_item_set_text(pi, "Type: Reserved (%#" G_GINT64_MODIFIER "x)", frame_type);
    } else {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val64_to_str_const(frame_type, http3_frame_types, "Unknown"));
    }

    proto_tree_add_item_ret_varint(tree, hf_http3_frame_length, tvb, offset, -1, ENC_VARINT_QUIC, &frame_length, &lenvar);
    offset += lenvar;

    if (frame_length) {
        switch (frame_type) {
#ifdef HAVE_NGHTTP3
            case HTTP3_FRAME_TYPE_HEADERS:
                dissect_http3_headers(tvb, pinfo, tree, offset, frame_length, h3_stream);
                break;
#endif
            default:
                proto_tree_add_item(tree, hf_http3_frame_payload, tvb, offset, (int)frame_length, ENC_NA);
        }
        offset += (int)frame_length;
    }

    return offset;
}

static void
report_unknown_stream_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, quic_stream_info *stream_info, http3_stream_info *h3_stream)
{
    /*
     * "If the stream header indicates a stream type which is not supported by
     * the recipient, the remainder of the stream cannot be consumed as the
     * semantics are unknown."
     * https://tools.ietf.org/html/draft-ietf-quic-http-23#page-22
     */
    proto_tree_add_expert_format(tree, pinfo, &ei_http3_unknown_stream_type, tvb, offset, 0,
                                 "Unknown stream type %#" G_GINT64_MODIFIER "x on Stream ID %#" G_GINT64_MODIFIER "x",
                                 h3_stream->uni_stream_type, stream_info->stream_id);
}

static int
dissect_http3_uni_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, quic_stream_info *stream_info, http3_stream_info *h3_stream)
{
    guint64 stream_type;
    int lenvar;
    proto_item *pi;

    if (stream_info->offset == 0) {
        pi = proto_tree_add_item_ret_varint(tree, hf_http3_stream_type, tvb, offset, -1, ENC_VARINT_QUIC, &stream_type, &lenvar);
        offset += lenvar;
        if (http3_is_reserved_code(stream_type)) {
            // Reserved to exercise requirement that unknown types are ignored.
            proto_item_set_text(pi, "Stream Type: Reserved (%#" G_GINT64_MODIFIER "x)", stream_type);
        }
        h3_stream->uni_stream_type = stream_type;
    } else {
        stream_type = h3_stream->uni_stream_type;
    }

    switch (stream_type) {
        case HTTP3_STREAM_TYPE_CONTROL:
            break;
        case HTTP3_STREAM_TYPE_PUSH:
            // The remaining data of this stream consists of HTTP/3 frames.
            if (stream_info->offset == 0) {
                proto_tree_add_item_ret_varint(tree, hf_http3_push_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;
            }
            break;
        case HTTP3_STREAM_TYPE_QPACK_ENCODER:
            // TODO
#ifdef HAVE_NGHTTP3
            {
                gint remaining = tvb_captured_length_remaining(tvb, offset);

                if (remaining > 0) {

                    http3_session *h3_session = get_http3_session(pinfo);
                    nghttp3_qpack_decoder *decoder = h3_session->qpack_decoders[h3_stream->dir];

                    // Get a coalesced copy of the TVB payload into the nghttp3 buffer
                    const uint8_t *qpack_buf = tvb_memdup(wmem_file_scope(), tvb, offset, remaining);

                    nghttp3_ssize  nread = nghttp3_qpack_decoder_read_encoder(decoder, qpack_buf, remaining);
                    uint64_t       icnt = nghttp3_qpack_decoder_get_icnt(decoder);

                    if (nread > 0) {
                        proto_tree_add_expert_format(tree, pinfo, &ei_http3_qpack_enc_update, tvb, offset, remaining,
                                "QPACK: successfully decoded encoder stream dir=%1d nread=%ld size=%d icnt=%llu",
                                h3_stream->dir,
                                nread,
                                remaining,
                                icnt);
                    } else {
                        proto_tree_add_expert_format(tree, pinfo, &ei_http3_qpack_failed, tvb, offset, 0,
                                "QPACK: failed to decode dir=%1d nread=%ld size=%d icnt=%llu",
                                h3_stream->dir,
                                nread,
                                remaining,
                                icnt);
                    }
                }
            }
#endif
            offset = tvb_captured_length(tvb);
            break;
        case HTTP3_STREAM_TYPE_QPACK_DECODER:
            // TODO
            offset = tvb_captured_length(tvb);
            break;
        default:
            // Unknown or reserved stream type, consume everything.
            if (!http3_is_reserved_code(stream_type)) {
                if (!PINFO_FD_VISITED(pinfo)) {
                    h3_stream->broken_from_offset = stream_info->offset + offset;
                }
                report_unknown_stream_type(tvb, pinfo, tree, offset, stream_info, h3_stream);
            }
            offset = tvb_captured_length(tvb);
            break;
    }

    return offset;
}

#ifdef HAVE_NGHTTP3
static gboolean
qpack_decoder_del_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data) {
    nghttp3_qpack_decoder_del((nghttp3_qpack_decoder*)user_data);
    return FALSE;
}

static gboolean
qpack_stream_context_del_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data) {
    nghttp3_qpack_stream_context_del((nghttp3_qpack_stream_context*)user_data);
    return FALSE;
}

static void nghttp3_vprintf_log(int level, const char *fmt, va_list args) {
    int rv = vsnprintf(nghttp3_vprintf_arena, sizeof(nghttp3_vprintf_arena), fmt, args);
    if (rv > 0) {
        g_log(G_LOG_DOMAIN, level, "%s", nghttp3_vprintf_arena);
    } else {
        g_warning("Could not format nghttp3 log message: rv=%d level=%d fmt=\"%s\"",
            rv, level, fmt);
    }
}

static void nghttp3_warning_vprintf_cb(const char *fmt, va_list args) {
    nghttp3_vprintf_log(G_LOG_LEVEL_WARNING, fmt, args);
}

#endif

http3_session*
get_http3_session(packet_info *pinfo)
{
    http3_session* h3session;
    conversation_t* conversation = find_or_create_conversation(pinfo);

    h3session = (http3_session*)conversation_get_proto_data(conversation,
            proto_http3);
    if (!h3session) {
        h3session = wmem_new0(wmem_file_scope(), http3_session);
#ifdef HAVE_NGHTTP3
        for (int dir=0; dir < 2; dir++) {
            nghttp3_qpack_decoder **pdecoder = &(h3session->qpack_decoders[dir]);
            nghttp3_qpack_decoder_new(
                    pdecoder,
                    qpack_max_dtable_size,
                    qpack_max_blocked,
                    nghttp3_mem_default());
            nghttp3_qpack_decoder_set_dtable_cap(
                    *pdecoder,
                    qpack_max_dtable_size);

            wmem_register_callback(wmem_file_scope(), qpack_decoder_del_cb, *pdecoder);
        }

        nghttp3_set_debug_vprintf_callback(nghttp3_warning_vprintf_cb);
#endif
        conversation_add_proto_data(conversation, proto_http3, h3session);
    }

    return h3session;
}

static int
dissect_http3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    quic_stream_info *stream_info = (quic_stream_info *)data;
    proto_item *ti;
    proto_tree *http3_tree;
    int offset = 0;
    http3_stream_info *h3_stream;

    if (!stream_info) {
        return 0;
    }

    switch (QUIC_STREAM_TYPE(stream_info->stream_id)) {
        case QUIC_STREAM_CLIENT_BIDI:
            /* Used for HTTP requests and responses. */
            if (!http3_check_frame_size(tvb, pinfo, offset)) {
                return tvb_captured_length(tvb);
            }
            break;
        case QUIC_STREAM_SERVER_BIDI:
            /* "HTTP/3 does not use server-initiated bidirectional streams,
             * though an extension could define a use for these streams." */
            break;
        case QUIC_STREAM_CLIENT_UNI:
        case QUIC_STREAM_SERVER_UNI:
            break;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HTTP3");
    // Only clear the columns if this is the first HTTP/3 STREAM in the packet.
    if (!proto_is_frame_protocol(pinfo->layers, "http3")) {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    ti = proto_tree_add_item(tree, proto_http3, tvb, 0, -1, ENC_NA);
    http3_tree = proto_item_add_subtree(ti, ett_http3);

    h3_stream = (http3_stream_info *)quic_stream_get_proto_data(pinfo, stream_info);
    if (!h3_stream) {
        h3_stream = wmem_new0(wmem_file_scope(), http3_stream_info);
        h3_stream->dir = stream_info->from_server == 0 ? DOWNSTREAM : UPSTREAM;
        quic_stream_add_proto_data(pinfo, stream_info, h3_stream);
#ifdef HAVE_NGHTTP3
        nghttp3_qpack_stream_context_new(&h3_stream->sctx, stream_info->stream_id, nghttp3_mem_default());
        wmem_register_callback(wmem_file_scope(), qpack_stream_context_del_cb, h3_stream->sctx);
#endif
    }

    // If a STREAM has unknown data, everything afterwards cannot be dissected.
    if (h3_stream->broken_from_offset && h3_stream->broken_from_offset <= stream_info->offset + offset) {
        report_unknown_stream_type(tvb, pinfo, tree, offset, stream_info, h3_stream);
        return tvb_captured_length(tvb);
    }

    switch (QUIC_STREAM_TYPE(stream_info->stream_id)) {
        case QUIC_STREAM_CLIENT_BIDI:
            /* Used for HTTP requests and responses. */
            break;

        case QUIC_STREAM_SERVER_BIDI:
            /* "HTTP/3 does not use server-initiated bidirectional streams,
             * though an extension could define a use for these streams." */
            // XXX expert info?
            return tvb_captured_length(tvb);

        case QUIC_STREAM_CLIENT_UNI:
        case QUIC_STREAM_SERVER_UNI:
            offset = dissect_http3_uni_stream(tvb, pinfo, http3_tree, offset, stream_info, h3_stream);
            break;
    }

    while (tvb_reported_length_remaining(tvb, offset)) {
        if (!http3_check_frame_size(tvb, pinfo, offset)) {
            return tvb_captured_length(tvb);
        }
        offset = dissect_http3_frame(tvb, pinfo, http3_tree, offset, h3_stream);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_http3(void)
{
    expert_module_t *expert_http3;

    static hf_register_info hf[] = {
        { &hf_http3_stream_type,
          { "Stream Type", "http3.stream_type",
            FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(http3_stream_types), 0x0,
            NULL, HFILL }
        },
        { &hf_http3_push_id,
          { "Push ID", "http3.push_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_http3_frame_type,
          { "Type", "http3.frame_type",
            FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(http3_frame_types), 0x0,
            "Frame Type", HFILL }
        },
        { &hf_http3_frame_length,
          { "Length", "http3.frame_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Length of the Frame Payload", HFILL }
        },
        { &hf_http3_frame_payload,
          { "Frame Payload", "http3.frame_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_http3_header,
            { "Header", "http3.header",
               FT_NONE, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_http3_header_length,
            { "Header Length", "http3.header.length",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_http3_header_count,
            { "Header Count", "http3.header.count",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_http3_header_name_length,
            { "Name Length", "http3.header.name.length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_header_name,
            { "Name", "http3.header.name",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_header_value_length,
            { "Value Length", "http3.header.value.length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_header_value,
            { "Value", "http3.header.value",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

    };

    static gint *ett[] = {
        &ett_http3,
        &ett_http3_headers,
    };

    static ei_register_info ei[] = {
        { &ei_http3_unknown_stream_type,
          { "http3.unknown_stream_type", PI_UNDECODED, PI_WARN,
            "An unknown stream type was encountered", EXPFILL }
        },
        // TODO
        { &ei_http3_qpack_failed,
          { "http3.qpack_failed", PI_UNDECODED, PI_WARN,
            "Header decompression failed", EXPFILL }
        },
        { &ei_http3_qpack_enc_update,
          { "http3.qpack_encoder_update", PI_UNDECODED, PI_WARN,
            "Decoded QPACK encoder stream", EXPFILL }
        },
        { &ei_http3_header_nv,
          { "http3.header", PI_UNDECODED, PI_WARN,
            "Decoded HTTP3 header name/value", EXPFILL }
        },
        { &ei_http3_header_failed ,
          { "http3.header_failed", PI_UNDECODED, PI_WARN,
            "Failed to decode HTTP3 header name/value", EXPFILL }
        },
    };

    proto_http3 = proto_register_protocol("Hypertext Transfer Protocol Version 3", "HTTP3", "http3");

    proto_register_field_array(proto_http3, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_http3 = expert_register_protocol(proto_http3);
    expert_register_field_array(expert_http3, ei, array_length(ei));
}

void
proto_reg_handoff_http3(void)
{
    dissector_handle_t http3_handle;

    http3_handle = create_dissector_handle(dissect_http3, proto_http3);
    dissector_add_string("quic.proto", "h3", http3_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
