/*
 * Copyright (c) 2017 RaydoNetworks.
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ppp/packet.h>

#include <pppox/pppox.h>
#include <pppox/pppd/pppd.h>
#include <pppox/pppd/fsm.h>
#include <pppox/pppd/lcp.h>
#include <pppox/pppd/upap.h>
#include <pppox/pppd/chap-new.h>
#include <pppox/pppd/ipcp.h>

#include <vppinfra/hash.h>
#include <vppinfra/bihash_template.c>

pppox_main_t pppox_main;

// This function is adapted to oss pppd main.c:get_input.
// refer to pppoeclient_session_input to see what packets can
// be delivered here, if new protocol enabled, should modify
// there too.
int
consume_pppox_ctrl_pkt (u32 bi, vlib_buffer_t * b)
{
  pppox_main_t * pom = &pppox_main;
  u32 sw_if_index = vnet_buffer(b)->sw_if_index [VLIB_RX];
  pppox_virtual_interface_t *t = 0;
  u8 *p = 0;
  int i = 0;
  u16 protocol = 0;
  struct protent *protp;
  int len = vnet_buffer(b)->pppox.len;
  // Use virtual interface context index as pppd unit number.
  u8 unit = pom->virtual_interface_index_by_sw_if_index[sw_if_index];

  // If instance is deleted, simple return.
  t = pool_elt_at_index (pom->virtual_interfaces, unit);
  if (t == NULL) {
    return 1;
  }

  p = vlib_buffer_get_current (b);

  GETSHORT(protocol, p);
  // Our pppox frame will only have a 16B protocol field.
  len -= 2;

  /*
   * Toss all non-LCP packets unless LCP is OPEN.
   */
  if (protocol != PPP_LCP && lcp_fsm[unit].state != OPENED) {
    return 1;
  }

  /*
   * Until we get past the authentication phase, toss all packets
   * except LCP authentication packets.
   */
  // ZDY: we only support PAP/CHAP HERE.
  if (phase[unit] <= PHASE_AUTHENTICATE
      && !(protocol == PPP_LCP || protocol == PPP_PAP || protocol == PPP_CHAP)) {
    return 1;
  }

  /*
   * Upcall the proper protocol input routine.
   */
  for (i = 0; (protp = protocols[i]) != NULL; ++i) {
    if (protp->protocol == protocol && protp->enabled_flag) {
      (*protp->input)(unit, p, len);
      return 0;
    }
    if (protocol == (protp->protocol & ~0x8000) && protp->enabled_flag
        && protp->datainput != NULL) {
      (*protp->datainput)(unit, p, len);
      return 0;
    }
  }

  lcp_sprotrej(unit, p - PPP_HDRLEN, len + PPP_HDRLEN);

  return 1;
}


/*
 * restart_dead_client - restart dead pppoe client to reconnec.
 */
static void
pppox_restart_dead_client()
{
  pppox_main_t * pom = &pppox_main;
  pppox_virtual_interface_t * vif;

  pool_foreach (vif, pom->virtual_interfaces, ({
    int unit = pom->virtual_interface_index_by_sw_if_index[vif->sw_if_index];
    if (phase[unit] == PHASE_DEAD && vif->pppoe_session_allocated) {
      // notify pppoe to open session to start.
      static void (*pppoe_client_open_session_func) (u32 client_index) = 0;
      if (pppoe_client_open_session_func ==0 ) {
	pppoe_client_open_session_func = vlib_get_plugin_symbol("pppoeclient_plugin.so", "pppoe_client_open_session");
      }
      (*pppoe_client_open_session_func) (vif->pppoe_client_index);
      }
  }));
}

static uword
pppox_process (vlib_main_t * vm,
               vlib_node_runtime_t * rt,
               vlib_frame_t * f)
{
  uword event_type;
  uword * event_data = 0;

  while (1)
    {
      // 1 second loop serve as a tick to drive oss-pppd timers.
      // XXX: actually we can call timeleft(sys-vpp.c) to
      // figure out what timeout we need here, but current
      // pppd timer mininum is 1s, so it's enough to do
      // this in a tick manner.
      vlib_process_wait_for_event_or_clock (vm, 1); // 1 second.

      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
        {
        case ~0:
          pppd_calltimeout();
          // We need restart dead client due to various reason.
          pppox_restart_dead_client();
          break;
        }

      vec_reset_length (event_data);
    }

  /* NOTREACHED */
  return 0;
}

VLIB_REGISTER_NODE (pppox_process_node,static) = {
    .function = pppox_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "pppox-process",
    .process_log2_n_stack_bytes = 16,
};

static u8 *
format_pppox_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "pppox%d", dev_instance);
}

static uword
dummy_interface_tx (vlib_main_t * vm,
                    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

static clib_error_t *
pppox_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

static u8 *
pppox_build_rewrite (vnet_main_t * vnm,
                     u32 sw_if_index,
                     vnet_link_t link_type, const void *dst_address)
{
  // only need append a 16B protocol filed.
  int len = 2;
  u8 *rw = 0;

  vec_validate (rw, len - 1);

  switch (link_type)
    {
    case VNET_LINK_IP4:
      *((u16 *) rw) = clib_host_to_net_u16(PPP_PROTOCOL_ip4);
      break;
    case VNET_LINK_IP6:
      *((u16 *) rw) = clib_host_to_net_u16(PPP_PROTOCOL_ip6);
      break;
    default:
      break;
    }

  return rw;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (pppox_device_class,static) = {
  .name = "PPPPOX",
  .format_device_name = format_pppox_name,
  .tx_function = dummy_interface_tx,
  .admin_up_down_function = pppox_interface_admin_up_down,
};
/* *INDENT-ON* */

VNET_HW_INTERFACE_CLASS (pppox_hw_class,static) = {
  .name = "PPPOX",
  .build_rewrite = pppox_build_rewrite,
  // Do not need leverage adj, use default update adj with
  // our own rewrite to insert the ppp protocol field.
  //.update_adjacency = pppox_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

u32
pppox_allocate_interface (u32 pppoe_client_index)
{
  pppox_main_t * pom = &pppox_main;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  vnet_main_t *vnm = pom->vnet_main;
  pppox_virtual_interface_t *t = 0;
  int unit;

  pool_get_aligned (pom->virtual_interfaces, t, CLIB_CACHE_LINE_BYTES);
  memset (t, 0, sizeof (*t));

  t->pppoe_client_index = pppoe_client_index;
  
  if (vec_len (pom->free_pppox_hw_if_indices) > 0)
    {
      vnet_interface_main_t *im = &vnm->interface_main;
      hw_if_index = pom->free_pppox_hw_if_indices
        [vec_len (pom->free_pppox_hw_if_indices) - 1];
      _vec_len (pom->free_pppox_hw_if_indices) -= 1;

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->dev_instance = t - pom->virtual_interfaces;
      hi->hw_instance = hi->dev_instance;

      /* clear old stats of freed X before reuse */
      sw_if_index = hi->sw_if_index;
      vnet_interface_counter_lock (im);
      vlib_zero_combined_counter
        (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
         sw_if_index);
      vlib_zero_combined_counter (&im->combined_sw_if_counters
                                  [VNET_INTERFACE_COUNTER_RX],
                                  sw_if_index);
      vlib_zero_simple_counter (&im->sw_if_counters
                                [VNET_INTERFACE_COUNTER_DROP],
                                sw_if_index);
      vnet_interface_counter_unlock (im);
    }
  else
    {
      hw_if_index = vnet_register_interface
        (vnm, pppox_device_class.index, t - pom->virtual_interfaces,
         pppox_hw_class.index,  t - pom->virtual_interfaces);
      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->output_node_index = pppox_output_node.index;
    }

  t->hw_if_index = hw_if_index;
  t->sw_if_index = sw_if_index = hi->sw_if_index;

  vec_validate_init_empty (pom->virtual_interface_index_by_sw_if_index,
                           sw_if_index,
                           ~0);
  pom->virtual_interface_index_by_sw_if_index[sw_if_index] = t - pom->virtual_interfaces;

  si = vnet_get_sw_interface (vnm, sw_if_index);
  si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
  vnet_sw_interface_set_flags (vnm, sw_if_index,
                               VNET_SW_INTERFACE_FLAG_ADMIN_UP);


  unit = t - pom->virtual_interfaces;
  // pap client.
  upap[unit].us_user = NULL;
  upap[unit].us_userlen = 0;
  upap[unit].us_passwd = NULL;
  upap[unit].us_passwdlen = 0;

  // chap client.
  chap_client[unit].us_user = NULL;
  chap_client[unit].us_userlen = 0;
  chap_client[unit].us_passwd = NULL;
  chap_client[unit].us_passwdlen = 0;

  return hw_if_index;
}

void
pppox_handle_allocated_address (pppox_virtual_interface_t * t, u8 is_add)
{
  pppox_main_t * pom = &pppox_main;
  ip4_address_t our_adr_ipv4;
  fib_prefix_t pfx;

  // Configure ip4 address.
  our_adr_ipv4.as_u32 = t->our_addr;
  ip4_add_del_interface_address (pom->vlib_main, t->sw_if_index,
                                 (void *) &our_adr_ipv4,
                                 32, !is_add /*is_del*/);
  
  // Configure reverse route.
  pfx.fp_addr.ip4.as_u32 = t->his_addr;
  pfx.fp_len = 32; // always 32
  pfx.fp_proto = FIB_PROTOCOL_IP4;
  if ( is_add ) {
    fib_table_entry_path_add (0, &pfx,
			      FIB_SOURCE_PLUGIN_HI, FIB_ENTRY_FLAG_NONE,
			      fib_proto_to_dpo (pfx.fp_proto),
			      &pfx.fp_addr, t->sw_if_index, ~0,
			      1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
  } else {
    fib_table_entry_path_remove (0, &pfx,
			      FIB_SOURCE_PLUGIN_HI,
			      fib_proto_to_dpo (pfx.fp_proto),
			      &pfx.fp_addr, t->sw_if_index, ~0,
			      1, FIB_ROUTE_PATH_FLAG_NONE);
  }
}

void
pppox_free_interface(u32 hw_if_index)
{
  pppox_main_t * pom = &pppox_main;
  vnet_main_t *vnm = pom->vnet_main;
  vnet_hw_interface_t *hi;
  pppox_virtual_interface_t *t = 0;
  int unit;
  hi = vnet_get_hw_interface (vnm, hw_if_index);

  unit = pom->virtual_interface_index_by_sw_if_index[hi->sw_if_index];
  t = pool_elt_at_index (pom->virtual_interfaces, unit);

  // clean allocated address.
  // lcp_close will trigger the ip freeed if we have allocated one.
#if 0
  if (t->our_addr) {
    pppox_handle_allocated_address (t, 0);
   }
#endif

  // turn down underlying lcp.
  lcp_close (unit, "User request");

  vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 0 /* down */ );
  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, hi->sw_if_index);
  si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

  vec_add1 (pom->free_pppox_hw_if_indices, hw_if_index);

  pom->virtual_interface_index_by_sw_if_index[hi->sw_if_index] = ~0;

  pool_put (pom->virtual_interfaces,  t);

  // pap client.
  if (upap[unit].us_user) {
    vec_free (upap[unit].us_user);
    upap[unit].us_user = NULL;
    upap[unit].us_userlen = 0;
  }
  if (upap[unit].us_passwd) {
    vec_free (upap[unit].us_passwd);
    upap[unit].us_passwd = NULL;
    upap[unit].us_passwdlen = 0;
  }

  // chap client.
  if (chap_client[unit].us_user) {
    vec_free (chap_client[unit].us_user);
    chap_client[unit].us_user = NULL;
    chap_client[unit].us_userlen = 0;
  }
  if (chap_client[unit].us_passwd) {
    vec_free (chap_client[unit].us_passwd);
    chap_client[unit].us_passwd = NULL;
    chap_client[unit].us_passwdlen = 0;
  }
}

void
pppox_lower_up(u32 sw_if_index)
{
  pppox_main_t * pom = &pppox_main;
  pppox_virtual_interface_t *t = 0;
  int unit;

  unit = pom->virtual_interface_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index (pom->virtual_interfaces, unit);
  t->pppoe_session_allocated = 1;

  new_phase (unit, PHASE_INITIALIZE);
  // Reset state due to lower reset.
  {
    struct protent *protp;
    for (int i = 0; (protp = protocols[i]) != NULL; ++i)
      {
	(*protp->init) (unit);
      }

    // Init auth context.
    init_auth_context (unit);
  }
  
  lcp_open(unit);
  start_link(unit);

  return;
}
// TODO: handle carrier status and pppoe sessiond down (PADT is not processed now).
void
pppox_lower_down(u32 sw_if_index)
{
  pppox_main_t * pom = &pppox_main;
  pppox_virtual_interface_t *t = 0;
  u8 unit;

  unit = pom->virtual_interface_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index (pom->virtual_interfaces, unit);
  
  lcp_close(unit, "lower down (remote close session/underlying physical interface down");

  t->pppoe_session_allocated = 0;

  return;
}

int
pppox_set_auth (u32 sw_if_index, u8 * username, u8 * password)
{
  pppox_main_t * pom = &pppox_main;
  pppox_virtual_interface_t *t = 0;
  int unit;

  unit = pom->virtual_interface_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index (pom->virtual_interfaces, unit);
  
  unit = pom->virtual_interface_index_by_sw_if_index[sw_if_index];

  // pap client.
  if (upap[unit].us_user) {
    vec_free (upap[unit].us_user);
  }
  upap[unit].us_user = (char *)vec_dup (username);
  upap[unit].us_userlen = strlen (upap[unit].us_user);
  if (upap[unit].us_passwd) {
    vec_free (upap[unit].us_passwd);
  }
  upap[unit].us_passwd = (char *) vec_dup(password);
  upap[unit].us_passwdlen = strlen (upap[unit].us_passwd);

  // chap client.
  if (chap_client[unit].us_user) {
    vec_free (chap_client[unit].us_user);
  }
  chap_client[unit].us_user = (char *) vec_dup(username);
  chap_client[unit].us_userlen = strlen (chap_client[unit].us_user);
  if (chap_client[unit].us_passwd) {
    vec_free (chap_client[unit].us_passwd);
  }
  chap_client[unit].us_passwd = (char *) vec_dup(password);
  chap_client[unit].us_passwdlen = strlen (chap_client[unit].us_passwd);

  // after auth configured, notify pppoe to open session to start.
  static void (*pppoe_client_open_session_func) (u32 client_index) = 0;
  if (pppoe_client_open_session_func ==0 ) {
    pppoe_client_open_session_func = vlib_get_plugin_symbol("pppoeclient_plugin.so", "pppoe_client_open_session");
  }
  (*pppoe_client_open_session_func) (t->pppoe_client_index);
  
  return 0;
}

clib_error_t *
pppox_init (vlib_main_t * vm)
{
  pppox_main_t *pom = &pppox_main;

  pom->vnet_main = vnet_get_main ();
  pom->vlib_main = vm;

  return 0;
}

VLIB_INIT_FUNCTION (pppox_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "PPPoX",
};
/* *INDENT-ON* */

// pppd-->vpp interaction.

/********************************************************************
 *
 * output - Output PPP packet through pppox virtual interface node.
 */
void output (int unit, u8 *p, int len)
{
  pppox_main_t * pom = &pppox_main;
  vlib_main_t * vm = vlib_get_main();
  vnet_main_t * vnm = pom->vnet_main;
  vlib_buffer_t * b;
  u32 bi;
  u32 * to_next;
  vlib_frame_t * f;
  pppox_virtual_interface_t *t = 0;
  vnet_hw_interface_t *hw;

  t = pool_elt_at_index (pom->virtual_interfaces, unit);
  if (t == NULL) {
    // PPPoE client might be deleted, simple return.
    return;
  }

  hw = vnet_get_hw_interface (vnm, t->hw_if_index);
  // TODO: should we should use packet template to prevent allocate buffer????
  if (vlib_buffer_alloc (vm, &bi, 1) != 1) {
    clib_warning ("buffer allocation failure");
    return;
  }
  b = vlib_get_buffer (vm, bi);

  ASSERT (b->current_data == 0);

  f = vlib_get_frame_to_node (vm, hw->output_node_index);
  // XXX: if later we suppport other X of PPPoX, we should check
  // remove ppp framing address and control field for PPPoE encap.
  p += 2;
  len -= 2;

  clib_memcpy(vlib_buffer_get_current(b), p, len);
  b->current_length = len;
  // Set tx if index to pppox virtual if index.
  vnet_buffer(b)->sw_if_index[VLIB_TX] = t->sw_if_index;

  /* Enqueue the packet right now */
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;

  vlib_put_frame_to_node (vm, hw->output_node_index, f);
}

typedef struct
{
  int unit;
  int is_add;
  u32 our_adr;
  u32 his_adr;
  u32 net_mask;
} ifaddr_arg_t;

static void *
ifaddr_callback (void *arg)
{
  pppox_main_t * pom = &pppox_main;
  pppox_virtual_interface_t * t;
  ifaddr_arg_t *a = arg;

  t = pool_elt_at_index (pom->virtual_interfaces, a->unit);

  if (a->is_add)
    {
      t->our_addr = a->our_adr;
      t->his_addr = a->his_adr;
      pppox_handle_allocated_address (t, 1);
    }
  else
    {
      pppox_handle_allocated_address (t, 0);
      t->our_addr = t->his_addr = 0;
    }

  return 0;
}

void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);

/********************************************************************
 *
 * sifaddr - Config the interface IP addresses and netmask.
 */
int sifaddr (int unit, u32 our_adr, u32 his_adr,
             u32 net_mask)
{
  ifaddr_arg_t a;

  memset (&a, 0, sizeof (a));
  a.unit = unit;
  // NB: oss-pppd pass network endian u32 here, and vpp fib
  // parameter require u32 too, so not conversion here.
  a.our_adr = our_adr;
  a.his_adr = his_adr;
  // oss-pppd passed net_mask is not used, always treat as host address.
  net_mask = net_mask;
  a.net_mask = 32;
  a.is_add = 1;

  // Add route in main thread, otherwise it will crash when
  // fib code do barrier check because we will then waiting for
  // our barrier finished...
  vl_api_rpc_call_main_thread (ifaddr_callback,
                               (u8 *) & a, sizeof (a));

  return 1;
}

/********************************************************************
 *
 * cifaddr - Clear the interface IP addresses, and delete routes
 * through the interface if possible.
 */

int cifaddr (int unit, u32 our_adr, u32 his_adr)
{
  ifaddr_arg_t a;

  memset (&a, 0, sizeof (a));
  a.unit = unit;
  // NB: oss-pppd pass network endian u32 here, and vpp fib
  // parameter require u32 too, so not conversion here.
  // NB: just record them here, we will use the address
  // we recorded on virtual interface to delete.
  a.our_adr = our_adr;
  a.his_adr = his_adr;
  a.net_mask = 32;
  a.is_add = 0;

  // Add route in main thread, otherwise it will crash when
  // fib code do barrier check because we will then waiting for
  // our barrier finished...
  vl_api_rpc_call_main_thread (ifaddr_callback,
                               (u8 *) & a, sizeof (a));

  return 1;
}

typedef struct
{
  int unit;
} cleanup_arg_t;

static void *
cleanup_callback (void *arg)
{
  pppox_main_t * pom = &pppox_main;
  pppox_virtual_interface_t * t;
  cleanup_arg_t *a = arg;

  t = pool_elt_at_index (pom->virtual_interfaces, a->unit);
  // notify pppoe to close session.
  static void (*pppoe_client_close_session_func) (u32 client_index) = 0;
  if (pppoe_client_close_session_func ==0 ) {
    pppoe_client_close_session_func = vlib_get_plugin_symbol("pppoeclient_plugin.so", "pppoe_client_close_session");
  }
  (*pppoe_client_close_session_func) (t->pppoe_client_index);  
  
  return 0;
}

int channel_cleanup (int unit)
{
  ifaddr_arg_t a;

  memset (&a, 0, sizeof (a));
  a.unit = unit;

  // Might be called in worker thread, so use rpc.
  vl_api_rpc_call_main_thread (cleanup_callback,
                               (u8 *) & a, sizeof (a));

  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
