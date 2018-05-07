/*
 *------------------------------------------------------------------
 * pppoeclient_api.c - pppoe client api
 *
 * Copyright (c) 2017 RaydoNetworks.
 *------------------------------------------------------------------
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>

#include <pppoeclient/pppoeclient.h>


#define vl_msg_id(n,h) n,
typedef enum
{
#include <pppoeclient/pppoeclient.api.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <pppoeclient/pppoeclient.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <pppoeclient/pppoeclient.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <pppoeclient/pppoeclient.api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <pppoeclient/pppoeclient.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <pppoeclient/pppoeclient.api.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE pem->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
setup_message_id_table (pppoeclient_main_t * pem, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + pem->msg_id_base);
  foreach_vl_msg_name_crc_pppoeclient;
#undef _
}

#define foreach_pppoeclient_plugin_api_msg                             \
_(PPPOE_ADD_DEL_CLIENT, pppoe_add_del_client)                           \
_(PPPOE_CLIENT_DUMP, pppoe_client_dump)

static void vl_api_pppoe_add_del_client_t_handler
  (vl_api_pppoe_add_del_client_t * mp)
{
  vl_api_pppoe_add_del_client_reply_t *rmp;
  int rv = 0;
  pppoeclient_main_t *pem = &pppoeclient_main;

  vnet_pppoe_add_del_client_args_t a = {
    .is_add = mp->is_add,
    .sw_if_index = ntohl (mp->sw_if_index),
    .host_uniq = ntohl (mp->host_uniq),
  };

  u32 pppox_sw_if_index = ~0;
  rv = vnet_pppoe_add_del_client (&a, &pppox_sw_if_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_PPPOE_ADD_DEL_CLIENT_REPLY,
  ({
    rmp->pppox_sw_if_index = ntohl (pppox_sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void send_pppoe_client_details
  (pppoe_client_t * t, unix_shared_memory_queue_t * q, u32 context)
{
  vl_api_pppoe_client_details_t *rmp;
  /* ip4_main_t *im4 = &ip4_main; */
  /* ip6_main_t *im6 = &ip6_main; */

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_PPPOE_CLIENT_DETAILS);
  /* if (is_ipv6) */
  /*   { */
  /*     memcpy (rmp->client_ip, t->client_ip.ip6.as_u8, 16); */
  /*     rmp->decap_vrf_id = htonl (im6->fibs[t->decap_fib_index].ft_table_id); */
  /*   } */
  /* else */
  /*   { */
  /*     memcpy (rmp->client_ip, t->client_ip.ip4.as_u8, 4); */
  /*     rmp->decap_vrf_id = htonl (im4->fibs[t->decap_fib_index].ft_table_id); */
  /*   } */
  /* rmp->session_id = htons (t->session_id); */
  /* rmp->encap_if_index = htonl (t->encap_if_index); */
  /* clib_memcpy (rmp->local_mac, t->local_mac, 6); */
  /* clib_memcpy (rmp->client_mac, t->client_mac, 6); */
  /* rmp->sw_if_index = htonl (t->sw_if_index); */
  /* rmp->is_ipv6 = is_ipv6; */
  /* rmp->context = context; */

  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

static void
vl_api_pppoe_client_dump_t_handler (vl_api_pppoe_client_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  pppoeclient_main_t *pem = &pppoeclient_main;
  pppoe_client_t *t;
  //u32 sw_if_index;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  // TODO: use query para. sw_if_index = ntohl (mp->sw_if_index);
  pool_foreach (t, pem->clients,
		({
		  send_pppoe_client_details(t, q, mp->context);
		}));
}


static clib_error_t *
pppoeclient_api_hookup (vlib_main_t * vm)
{
  pppoeclient_main_t *pem = &pppoeclient_main;

  u8 *name = format (0, "pppoeclient_%08x%c", api_version, 0);
  pem->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + pem->msg_id_base),     \
                           #n,                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_pppoeclient_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (pem, &api_main);

  return 0;
}

VLIB_API_INIT_FUNCTION (pppoeclient_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
