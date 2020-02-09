/* packet-udpcp.c
 *
 * Routines for UDPCP packet dissection (UDP-based reliable communication protocol).
 * Described in the Open Base Station Initiative Reference Point 1 Specification
 * (see http://www.obsai.com/specs/RP1%20Spec%20v2_1.pdf, Appendix A)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* TODO:
 * - Check for expected Acks and link between Data and Ack frames
 * - Verify length parameter against remaining payload
 * - Calculate/verify Checksum field
 * - Sequence number analysis, i.e.
 *     - check next expected Msg Id
 *     - flag out-of-order Fragment Number within a MsgId?
 * - Duplicate Message Detection (A.3.2.4)
 * */

#include <stdio.h>
#include "config.h"

#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>

void proto_register_udpcp(void);

static int proto_udpcp = -1;

static int hf_udpcp_checksum = -1;
static int hf_udpcp_msg_type = -1;
static int hf_udpcp_version = -1;

static int hf_udpcp_n = -1;
static int hf_udpcp_c = -1;
static int hf_udpcp_s = -1;
static int hf_udpcp_d = -1;
static int hf_udpcp_reserved = -1;

static int hf_udpcp_fragment_amount = -1;
static int hf_udpcp_fragment_number = -1;

static int hf_udpcp_message_id = -1;
static int hf_udpcp_message_data_length = -1;

static int hf_udpcp_payload = -1;

/* For reassembly */
static int hf_udpcp_fragments = -1;
static int hf_udpcp_fragment = -1;
static int hf_udpcp_fragment_overlap = -1;
static int hf_udpcp_fragment_overlap_conflict = -1;
static int hf_udpcp_fragment_multiple_tails = -1;
static int hf_udpcp_fragment_too_long_fragment = -1;
static int hf_udpcp_fragment_error = -1;
static int hf_udpcp_fragment_count = -1;
static int hf_udpcp_reassembled_in = -1;
static int hf_udpcp_reassembled_length = -1;
static int hf_udpcp_reassembled_data = -1;


/* Subtrees */
static gint ett_udpcp = -1;
static gint ett_udpcp_fragments = -1;
static gint ett_udpcp_fragment  = -1;

static const fragment_items udpcp_frag_items = {
  &ett_udpcp_fragment,
  &ett_udpcp_fragments,
  &hf_udpcp_fragments,
  &hf_udpcp_fragment,
  &hf_udpcp_fragment_overlap,
  &hf_udpcp_fragment_overlap_conflict,
  &hf_udpcp_fragment_multiple_tails,
  &hf_udpcp_fragment_too_long_fragment,
  &hf_udpcp_fragment_error,
  &hf_udpcp_fragment_count,
  &hf_udpcp_reassembled_in,
  &hf_udpcp_reassembled_length,
  &hf_udpcp_reassembled_data,
  "UDPCP fragments"
};



static dissector_handle_t udpcp_handle;


void proto_reg_handoff_udpcp (void);

/* User definable values */
static range_t *global_udpcp_port_range = NULL;

#define DATA_FORMAT 0x01
#define ACK_FORMAT  0x02


static const value_string msg_type_vals[] = {
  { DATA_FORMAT,   "Data Packet" },
  { ACK_FORMAT,    "Ack Packet" },
  { 0,     NULL }
};


/* Reassembly table. */
static reassembly_table udpcp_reassembly_table;

static guint udpcp_hash(gconstpointer k _U_)
{
    return GPOINTER_TO_UINT(k);
}

static gint udpcp_equal(gconstpointer k1, gconstpointer k2)
{
    return k1 == k2;
}

static gpointer udpcp_temporary_key(const packet_info *pinfo _U_, const guint32 id _U_, const void *data _U_)
{
    return (gpointer)data;
}

static gpointer udpcp_persistent_key(const packet_info *pinfo _U_, const guint32 id _U_,
                                     const void *data)
{
    return (gpointer)data;
}

static void udpcp_free_temporary_key(gpointer ptr _U_)
{
}

static void udpcp_free_persistent_key(gpointer ptr _U_)
{
}

reassembly_table_functions udpcp_reassembly_table_functions =
{
    udpcp_hash,
    udpcp_equal,
    udpcp_temporary_key,
    udpcp_persistent_key,
    udpcp_free_temporary_key,
    udpcp_free_persistent_key
};


/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

/* Reassemble by default */
static gboolean global_udpcp_reassemble = TRUE;

/* By default do try to decode payload as XML/SOAP */
static gboolean global_udpcp_decode_payload_as_soap = TRUE;


/******************************/
/* Main dissection function.  */
static int
dissect_udpcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *udpcp_tree;
    proto_item *root_ti;
    gint offset = 0;

    /* Must be at least 12 bytes */
    if (tvb_reported_length(tvb) < 12) {
        return 0;
    }

    /* Must be Data or Ack format. */
    guint32 msg_type = tvb_get_guint8(tvb, 4) >> 6;
    if (msg_type != DATA_FORMAT && msg_type != ACK_FORMAT) {
        return 0;
    }

    /* Protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDPCP");

    /* Protocol root */
    root_ti = proto_tree_add_item(tree, proto_udpcp, tvb, offset, -1, ENC_NA);
    udpcp_tree = proto_item_add_subtree(root_ti, ett_udpcp);

    /* Checksum */
    proto_tree_add_item(udpcp_tree, hf_udpcp_checksum, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Msg-type */
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN, &msg_type);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                 (msg_type == 0x01) ? "[Data] " : "[Ack]  ");

    /* Version */
    proto_tree_add_item(udpcp_tree, hf_udpcp_version, tvb, offset, 1, ENC_BIG_ENDIAN);

    /* Packet Transfer Options */
    guint32 n, s;
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_n, tvb, offset, 1, ENC_BIG_ENDIAN, &n);
    proto_tree_add_item(udpcp_tree, hf_udpcp_c, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_s, tvb, offset, 1, ENC_BIG_ENDIAN, &s);
    offset++;
    proto_tree_add_item(udpcp_tree, hf_udpcp_d, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(udpcp_tree, hf_udpcp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* Fragment Amount & Fragment Number */
    guint32 fragment_amount, fragment_number;
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_fragment_amount, tvb, offset, 1, ENC_BIG_ENDIAN, &fragment_amount);
    offset++;
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_fragment_number, tvb, offset, 1, ENC_BIG_ENDIAN, &fragment_number);
    offset++;

    /* Message ID & Message Data Length */
    guint32 message_id;
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_message_id, tvb, offset, 2, ENC_BIG_ENDIAN, &message_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, " Msg_ID=%3u", message_id);
    offset += 2;
    guint32 data_length;
    proto_tree_add_item_ret_uint(udpcp_tree, hf_udpcp_message_data_length, tvb, offset, 2, ENC_BIG_ENDIAN, &data_length);
    offset += 2;

    /* Data could follow here */
    if (msg_type == DATA_FORMAT) {

        if (!data_length) {
            /* This could just  be a sync frame */
            if (message_id == 0 && n==0 && s==0) {
                col_append_str(pinfo->cinfo, COL_INFO, "  [Sync]");
            }
            /* Nothing more to show here */
            return offset;
        }

        /* Show fragment numbering.  Ignore confusing 0-based fragment numbering.. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "  [Frag %u/%u]",
                        fragment_number+1, fragment_amount);

        /* There is data */
        if ((fragment_amount == 1) && (fragment_number == 0)) {
            /* Not fragmented - show payload now */
            proto_tree_add_item(udpcp_tree, hf_udpcp_payload, tvb, offset, -1, ENC_ASCII);
            col_append_fstr(pinfo->cinfo, COL_INFO, "  Data (%u bytes)", data_length);

            if (global_udpcp_decode_payload_as_soap) {
                /* Send to XML dissector */
                dissector_handle_t xml_handle = find_dissector("xml");
                tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector_only(xml_handle, next_tvb, pinfo, tree, NULL);
            }
        }
        else {
            /* Fragmented */
            if (global_udpcp_reassemble) {
                /* Reassembly */
                /* Set fragmented flag. */
                gboolean save_fragmented = pinfo->fragmented;
                pinfo->fragmented = TRUE;
                fragment_head *fh;
                guint frag_data_len = tvb_reported_length_remaining(tvb, offset);

                /* Add this fragment into reassembly */
                fh = fragment_add_seq_check(&udpcp_reassembly_table, tvb, offset, pinfo,
                                            message_id,                                    /* id */
                                            GUINT_TO_POINTER(message_id),                  /* data */
                                            fragment_number,                               /* frag_number */
                                            frag_data_len,                                 /* frag_data_len */
                                            (fragment_number < (fragment_amount-1))        /* more_frags */
                                            );

                gboolean update_col_info = TRUE;
                /* See if this completes a PDU */
                tvbuff_t *next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled UDPCP Payload",
                                                              fh, &udpcp_frag_items,
                                                              &update_col_info, udpcp_tree);
                if (next_tvb) {
                    /* Have reassembled data */
                    proto_tree_add_item(udpcp_tree, hf_udpcp_payload, next_tvb, 0, -1, ENC_ASCII);
                    col_append_fstr(pinfo->cinfo, COL_INFO, "  Reassembled Data (%u bytes)", data_length);

                    if (global_udpcp_decode_payload_as_soap) {
                        /* Send to XML dissector */
                        dissector_handle_t xml_handle = find_dissector("xml");
                        call_dissector_only(xml_handle, next_tvb, pinfo, tree, NULL);
                    }
                }

                /* Restore fragmented flag */
                pinfo->fragmented = save_fragmented;
            }
        }
    }

    return offset;
}


void
proto_register_udpcp(void)
{
  static hf_register_info hf[] = {
    { &hf_udpcp_checksum,
      { "Checksum", "udpcp.checksum", FT_UINT32, BASE_HEX,
        NULL, 0x0, "Adler32 checksum", HFILL }},
      { &hf_udpcp_msg_type,
        { "Msg Type", "udpcp.msg-type", FT_UINT8, BASE_HEX,
          VALS(msg_type_vals), 0xc0, NULL, HFILL }},
      { &hf_udpcp_version,
        { "Version", "udpcp.version", FT_UINT8, BASE_HEX,
          NULL, 0x38, NULL, HFILL }},

      { &hf_udpcp_n,
        { "N", "udpcp.n", FT_UINT8, BASE_HEX,
          NULL, 0x04, "Along with S bit, indicates whether acknowledgements should be sent", HFILL }},
      { &hf_udpcp_c,
        { "C", "udpcp.c", FT_UINT8, BASE_HEX,
          NULL, 0x02, "When set, the checksum should be valid", HFILL }},
      { &hf_udpcp_s,
        { "S", "udpcp.s", FT_UINT8, BASE_HEX,
          NULL, 0x01, "Along with N bit, indicates whether acknowledgements should be sent", HFILL }},
      { &hf_udpcp_d,
        { "D", "udpcp.d", FT_UINT8, BASE_HEX,
          NULL, 0x80, "For ACK, indicates duplicate ACK", HFILL }},
      { &hf_udpcp_reserved,
        { "Reserved", "udpcp.reserved", FT_UINT8, BASE_HEX,
          NULL, 0x7f, "Shall be set to 0", HFILL }},

      { &hf_udpcp_fragment_amount,
        { "Fragment Amount", "udpcp.fragment-amount", FT_UINT8, BASE_DEC,
          NULL, 0x0, "Total number of fragments of a mesage", HFILL }},
      { &hf_udpcp_fragment_number,
        { "Fragment Number", "udpcp.fragment-number", FT_UINT8, BASE_DEC,
          NULL, 0x0, "Fragment number of current packet within msg.  Starts at 0", HFILL }},

      { &hf_udpcp_message_id,
        { "Message ID", "udpcp.message-id", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_udpcp_message_data_length,
        { "Message Data Length", "udpcp.message-data-length", FT_UINT16, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},

      { &hf_udpcp_payload,
        { "Payload", "udpcp.payload", FT_BYTES, BASE_SHOW_ASCII_PRINTABLE,
          NULL, 0x0, "Complete or reassembled payload", HFILL }},

      /* Reassembly */
      { &hf_udpcp_fragment,
        { "Fragment", "udpcp.fragment", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_udpcp_fragments,
        { "Fragments", "udpcp.fragments", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL }},
      { &hf_udpcp_fragment_overlap,
        { "Fragment overlap", "udpcp.fragment.overlap", FT_BOOLEAN, BASE_NONE,
          NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
      { &hf_udpcp_fragment_overlap_conflict,
        { "Conflicting data in fragment overlap", "udpcp.fragment.overlap.conflict",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Overlapping fragments contained conflicting data", HFILL }},
      { &hf_udpcp_fragment_multiple_tails,
        { "Multiple tail fragments found", "udpcp.fragment.multipletails",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Several tails were found when defragmenting the packet", HFILL }},
      { &hf_udpcp_fragment_too_long_fragment,
        { "Fragment too long", "udpcp.fragment.toolongfragment",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Fragment contained data past end of packet", HFILL }},
      { &hf_udpcp_fragment_error,
        { "Defragmentation error", "udpcp.fragment.error", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},
      { &hf_udpcp_fragment_count,
        { "Fragment count", "udpcp.fragment.count", FT_UINT32, BASE_DEC,
          NULL, 0x0, NULL, HFILL }},
      { &hf_udpcp_reassembled_in,
        { "Reassembled payload in frame", "udpcp.reassembled_in", FT_FRAMENUM, BASE_NONE,
        NULL, 0x0, "This payload packet is reassembled in this frame", HFILL }},
      { &hf_udpcp_reassembled_length,
        { "Reassembled payload length", "udpcp.reassembled.length", FT_UINT32, BASE_DEC,
          NULL, 0x0, "The total length of the reassembled payload", HFILL }},
      { &hf_udpcp_reassembled_data,
        { "Reassembled codeblocks", "udpcp.reassembled.data", FT_BYTES, BASE_NONE,
          NULL, 0x0, "The reassembled payload", HFILL }},
    };

    static gint *ett[] = {
        &ett_udpcp,
        &ett_udpcp_fragments,
        &ett_udpcp_fragment
    };

    module_t *udpcp_module;

    proto_udpcp = proto_register_protocol("UDPCP", "UDPCP", "udpcp");
    proto_register_field_array(proto_udpcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    udpcp_handle = register_dissector("udpcp", dissect_udpcp, proto_udpcp);

    /* Register reassembly table. */
    reassembly_table_register(&udpcp_reassembly_table,
                              &udpcp_reassembly_table_functions);

    /* Preferences */
    udpcp_module = prefs_register_protocol(proto_udpcp, NULL);

    /* Payload reassembly */
    prefs_register_bool_preference(udpcp_module, "attempt_reassembly",
                                   "Reassemble payload",
                                   "",
                                   &global_udpcp_reassemble);

    /* Whether to try XML dissector on payload.
     * TODO: are there any other payload types we might see? */
    prefs_register_bool_preference(udpcp_module, "attempt_xml_decode",
        "Call XML dissector for payload",
        "",
        &global_udpcp_decode_payload_as_soap);
}

static void
apply_udpcp_prefs(void)
{
    global_udpcp_port_range = prefs_get_range_value("udpcp", "udp.port");
}

void
proto_reg_handoff_udpcp(void)
{
    dissector_add_uint_range_with_preference("udp.port", "", udpcp_handle);
    apply_udpcp_prefs();
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
