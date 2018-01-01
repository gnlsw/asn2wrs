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

#include "packet-foo-hf.c"

/* Initialize the subtree pointers */
static int ett_foo = -1;

#include "packet-foo-ett.c"

#include "packet-foo-fn.c"


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

#include "packet-foo-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_foo,
#include "packet-foo-ettarr.c"
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