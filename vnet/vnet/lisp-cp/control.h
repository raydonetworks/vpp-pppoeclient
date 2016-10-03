/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef VNET_CONTROL_H_
#define VNET_CONTROL_H_

#include <vnet/vnet.h>
#include <vnet/lisp-cp/gid_dictionary.h>
#include <vnet/lisp-cp/lisp_types.h>

#define NUMBER_OF_RETRIES                   1
#define PENDING_MREQ_EXPIRATION_TIME        3.0	/* seconds */
#define PENDING_MREQ_QUEUE_LEN              5

typedef struct
{
  gid_address_t src;
  gid_address_t dst;
  u32 retries_num;
  f64 time_to_expire;
  u8 is_smr_invoked;
  u64 *nonces;
  u8 to_be_removed;
} pending_map_request_t;

typedef struct
{
  gid_address_t leid;
  gid_address_t reid;
  locator_pair_t *locator_pairs;
} fwd_entry_t;

typedef enum
{
  IP4_MISS_PACKET,
  IP6_MISS_PACKET
} miss_packet_type_t;

typedef struct
{
  u8 is_down;
  f64 last_update;
  ip_address_t address;
} map_resolver_t;

typedef struct
{
  /* headers */
  u8 data[100];
  u32 length;
  miss_packet_type_t type;
} miss_packet_t;

typedef enum
{
  MR_MODE_DST_ONLY = 0,
  MR_MODE_SRC_DST,
  _MR_MODE_MAX
} map_request_mode_t;

typedef struct
{
  /* LISP feature status */
  u8 is_enabled;

  /* eid table */
  gid_dictionary_t mapping_index_by_gid;

  /* pool of mappings */
  mapping_t *mapping_pool;

  /* pool of locators */
  locator_t *locator_pool;

  /* pool of locator-sets */
  locator_set_t *locator_set_pool;

  /* vector of locator-set vectors composed of and indexed by locator index */
  u32 **locator_to_locator_sets;

  /* hash map of locators by name */
  uword *locator_set_index_by_name;

  /* vector of eid index vectors supported and indexed by locator-set index */
  u32 **locator_set_to_eids;

  /* vectors of indexes for local locator-sets and mappings */
  u32 *local_mappings_indexes;
  u32 *local_locator_set_indexes;

  /* hash map of forwarding entries by mapping index */
  u32 *fwd_entry_by_mapping_index;

  /* forwarding entries pool */
  fwd_entry_t *fwd_entry_pool;

  /* hash map keyed by nonce of pending map-requests */
  uword *pending_map_requests_by_nonce;

  /* pool of pending map requests */
  pending_map_request_t *pending_map_requests_pool;
  volatile u32 *pending_map_request_lock;

  /* vector of map-resolvers */
  map_resolver_t *map_resolvers;

  /* map resolver address currently being used for sending requests.
   * This has to be an actual address and not an index to map_resolvers vector
   * since the vector may be modified during request resend/retry procedure
   * and break things :-) */
  ip_address_t active_map_resolver;

  u8 do_map_resolver_election;

  /* map-request  locator set index */
  u32 mreq_itr_rlocs;

  /* vni to vrf hash tables */
  uword *table_id_by_vni;
  uword *vni_by_table_id;

  /* vni to bd-index hash tables */
  uword *bd_id_by_vni;
  uword *vni_by_bd_id;

  /* track l2 and l3 interfaces that have been created for vni */
  uword *l2_dp_intf_by_vni;

  /* Proxy ETR map index */
  u32 pitr_map_index;

  /* LISP PITR mode */
  u8 lisp_pitr;

  /* map request mode */
  u8 map_request_mode;

  /* commodity */
  ip4_main_t *im4;
  ip6_main_t *im6;
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} lisp_cp_main_t;

/* lisp-gpe control plane */
lisp_cp_main_t lisp_control_main;

extern vlib_node_registration_t lisp_cp_input_node;
extern vlib_node_registration_t lisp_cp_lookup_ip4_node;
extern vlib_node_registration_t lisp_cp_lookup_ip6_node;

clib_error_t *lisp_cp_init ();

always_inline lisp_cp_main_t *
vnet_lisp_cp_get_main ()
{
  return &lisp_control_main;
}

typedef struct
{
  u8 is_add;
  union
  {
    u8 *name;
    u32 index;
  };
  locator_t *locators;
  u8 local;
} vnet_lisp_add_del_locator_set_args_t;

int
vnet_lisp_add_del_locator_set (vnet_lisp_add_del_locator_set_args_t * a,
			       u32 * ls_index);
int
vnet_lisp_add_del_locator (vnet_lisp_add_del_locator_set_args_t * a,
			   locator_set_t * ls, u32 * ls_index);

typedef struct
{
  u8 is_add;
  gid_address_t eid;
  u32 locator_set_index;

  u32 ttl;
  u8 action;
  u8 authoritative;

  u8 local;
  u8 is_static;
} vnet_lisp_add_del_mapping_args_t;

int
vnet_lisp_map_cache_add_del (vnet_lisp_add_del_mapping_args_t * a,
			     u32 * map_index);
int
vnet_lisp_add_del_local_mapping (vnet_lisp_add_del_mapping_args_t * a,
				 u32 * map_index_result);

int
vnet_lisp_add_del_mapping (gid_address_t * deid, locator_t * dlocs, u8 action,
			   u8 authoritative, u32 ttl, u8 is_add, u8 is_static,
			   u32 * res_map_index);

typedef struct
{
  gid_address_t reid;
  gid_address_t leid;
  u8 is_add;
} vnet_lisp_add_del_adjacency_args_t;

int vnet_lisp_add_del_adjacency (vnet_lisp_add_del_adjacency_args_t * a);

typedef struct
{
  u8 is_add;
  ip_address_t address;
} vnet_lisp_add_del_map_resolver_args_t;

int
vnet_lisp_add_del_map_resolver (vnet_lisp_add_del_map_resolver_args_t * a);

clib_error_t *vnet_lisp_enable_disable (u8 is_enabled);
u8 vnet_lisp_enable_disable_status (void);

int vnet_lisp_pitr_set_locator_set (u8 * locator_set_name, u8 is_add);

typedef struct
{
  u8 is_add;
  u8 *locator_set_name;
} vnet_lisp_add_del_mreq_itr_rloc_args_t;

int
vnet_lisp_add_del_mreq_itr_rlocs (vnet_lisp_add_del_mreq_itr_rloc_args_t * a);

int vnet_lisp_clear_all_remote_adjacencies (void);

int vnet_lisp_eid_table_map (u32 vni, u32 vrf, u8 is_l2, u8 is_add);
int vnet_lisp_set_map_request_mode (u8 mode);
u8 vnet_lisp_get_map_request_mode (void);

static inline void
lisp_pending_map_request_lock (lisp_cp_main_t * lcm)
{
  if (lcm->pending_map_request_lock)
    while (__sync_lock_test_and_set (lcm->pending_map_request_lock, 1))
      /* sweet dreams */ ;
}

static inline void
lisp_pending_map_request_unlock (lisp_cp_main_t * lcm)
{
  if (lcm->pending_map_request_lock)
    *lcm->pending_map_request_lock = 0;
}

#endif /* VNET_CONTROL_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
