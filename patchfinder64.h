int InitPatchfinder(uint64_t base, const char *filename);
void TermPatchfinder(void);

// Fun part
uint64_t Find_allproc(void);
uint64_t Find_add_x0_x0_0x40_ret(void);
uint64_t Find_copyout(void);
uint64_t Find_bzero(void);
uint64_t Find_bcopy(void);
uint64_t Find_rootvnode(void);
uint64_t Find_trustcache(void);
uint64_t Find_amficache(void);
uint64_t Find_pmap_load_trust_cache_ppl(void);
uint64_t Find_OSBoolean_True(void);
uint64_t Find_OSBoolean_False(void);
uint64_t Find_zone_map_ref(void);
uint64_t Find_osunserializexml(void);
uint64_t Find_smalloc(void);
uint64_t Find_sbops(void);
uint64_t Find_bootargs(void);
uint64_t Find_vfs_context_current(void);
uint64_t Find_vnode_lookup(void);
uint64_t Find_vnode_put(void);
uint64_t Find_cs_gen_count(void);
uint64_t Find_cs_validate_csblob(void);
uint64_t Find_kalloc_canblock(void);
uint64_t Find_cs_blob_allocate_site(void);
uint64_t Find_kfree(void);
uint64_t Find_cs_find_md(void);
uint64_t Find_kernel_memory_allocate(void);
uint64_t Find_kernel_map(void);

// PAC
uint64_t Find_l2tp_domain_module_start(void);
uint64_t Find_l2tp_domain_module_stop(void);
uint64_t Find_l2tp_domain_inited(void);
uint64_t Find_sysctl_net_ppp_l2tp(void);
uint64_t Find_sysctl_unregister_oid(void);
uint64_t Find_mov_x0_x4__br_x5(void);
uint64_t Find_mov_x9_x0__br_x1(void);
uint64_t Find_mov_x10_x3__br_x6(void);
uint64_t Find_kernel_forge_pacia_gadget(void);
uint64_t Find_kernel_forge_pacda_gadget(void);
uint64_t Find_IOUserClient_vtable(void);
uint64_t Find_IORegistryEntry__getRegistryEntryID(void);
