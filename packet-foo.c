/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-foo.c                                                               */
/* asn2wrs.py -p foo -c foo.cnf -s packet-foo-template -d lypsatcmo foo.asn   */

/* Input file: packet-foo-template.c */

#line 1 "./wsl/asn2wrs/packet-foo-template.c"
/* packet-foo.c
 * Routines for FOO packet dissection
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-per.h"
#include "packet-foo.h"

#define PNAME  "FOO Protocol"
#define PSNAME "FOO"
#define PFNAME "foo"
#define FOO_PORT 5001    /* UDP port */
static dissector_handle_t foo_handle=NULL;

/* Initialize the protocol and registered fields */
static int proto_foo = -1;
static int global_foo_port = FOO_PORT;


/*--- Included file: packet-foo-hf.c ---*/
#line 1 "./wsl/asn2wrs/packet-foo-hf.c"
static int hf_foo_FOO_MESSAGE_PDU = -1;           /* FOO_MESSAGE */
static int hf_foo_name = -1;                      /* OCTET_STRING_SIZE_10 */
static int hf_foo_value = -1;                     /* OCTET_STRING_SIZE_10 */
static int hf_foo_messageId = -1;                 /* MessageId */
static int hf_foo_flowId = -1;                    /* FlowId */
static int hf_foo_messageData = -1;               /* MessageData */

/*--- End of included file: packet-foo-hf.c ---*/
#line 49 "./wsl/asn2wrs/packet-foo-template.c"

/* Initialize the subtree pointers */
static int ett_foo = -1;


/*--- Included file: packet-foo-ett.c ---*/
#line 1 "./wsl/asn2wrs/packet-foo-ett.c"
static gint ett_foo_MessageData = -1;
static gint ett_foo_FOO_MESSAGE = -1;

/*--- End of included file: packet-foo-ett.c ---*/
#line 54 "./wsl/asn2wrs/packet-foo-template.c"


/*--- Included file: packet-foo-fn.c ---*/
#line 1 "./wsl/asn2wrs/packet-foo-fn.c"


static int
dissect_foo_MessageId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_foo_FlowId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_foo_OCTET_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       10, 10, FALSE, NULL);

  return offset;
}


static const per_sequence_t MessageData_sequence[] = {
  { &hf_foo_name            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_foo_OCTET_STRING_SIZE_10 },
  { &hf_foo_value           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_foo_OCTET_STRING_SIZE_10 },
  { NULL, 0, 0, NULL }
};

static int
dissect_foo_MessageData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_foo_MessageData, MessageData_sequence);

  return offset;
}


static const per_sequence_t FOO_MESSAGE_sequence[] = {
  { &hf_foo_messageId       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_foo_MessageId },
  { &hf_foo_flowId          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_foo_FlowId },
  { &hf_foo_messageData     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_foo_MessageData },
  { NULL, 0, 0, NULL }
};

static int
dissect_foo_FOO_MESSAGE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_foo_FOO_MESSAGE, FOO_MESSAGE_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_FOO_MESSAGE_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_foo_FOO_MESSAGE(tvb, offset, &asn1_ctx, tree, hf_foo_FOO_MESSAGE_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-foo-fn.c ---*/
#line 56 "./wsl/asn2wrs/packet-foo-template.c"


static void
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        proto_item      *foo_item = NULL;
        proto_tree      *foo_tree = NULL;
        int                     offset = 0;


        /* make entry in the Protocol column on summary display */
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
                col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* create the foo protocol tree */
    if (tree) {
        foo_item = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, FALSE);
        foo_tree = proto_item_add_subtree(foo_item, ett_foo);

        dissect_FOO_MESSAGE_PDU(tvb, pinfo, foo_tree);
    }
}
/*--- proto_register_foo -------------------------------------------*/
void proto_register_foo(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-foo-hfarr.c ---*/
#line 1 "./wsl/asn2wrs/packet-foo-hfarr.c"
    { &hf_foo_FOO_MESSAGE_PDU,
      { "FOO-MESSAGE", "foo.FOO_MESSAGE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_foo_name,
      { "name", "foo.name",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_10", HFILL }},
    { &hf_foo_value,
      { "value", "foo.value",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_10", HFILL }},
    { &hf_foo_messageId,
      { "messageId", "foo.messageId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_foo_flowId,
      { "flowId", "foo.flowId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_foo_messageData,
      { "messageData", "foo.messageData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-foo-hfarr.c ---*/
#line 85 "./wsl/asn2wrs/packet-foo-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_foo,

/*--- Included file: packet-foo-ettarr.c ---*/
#line 1 "./wsl/asn2wrs/packet-foo-ettarr.c"
    &ett_foo_MessageData,
    &ett_foo_FOO_MESSAGE,

/*--- End of included file: packet-foo-ettarr.c ---*/
#line 91 "./wsl/asn2wrs/packet-foo-template.c"
  };


  /* Register protocol */
  proto_foo = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_foo, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

 


}


/*--- proto_reg_handoff_foo ---------------------------------------*/
void
proto_reg_handoff_foo(void)
{
    static gboolean inited = FALSE;

    if( !inited ) {

        foo_handle = create_dissector_handle(dissect_foo,
                                                     proto_foo);
        dissector_add("udp.port", global_foo_port, foo_handle);

        inited = TRUE;
    }

}