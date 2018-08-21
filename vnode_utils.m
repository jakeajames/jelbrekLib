//
//  *.c
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#import "kernel_utils.h"
#import "patchfinder64.h"
#import "offsetof.h"
#import "offsets.h"
#import "kexecute.h"
#import "kernelSymbolFinder.h"
#import <stdlib.h>

extern uint64_t kaslr_slide;

int vnode_lookup(const char *path, int flags, uint64_t *vnode, uint64_t vfs_context) {

    size_t len = strlen(path) + 1;
    uint64_t ptr = kalloc(8);
    uint64_t ptr2 = kalloc(len);
    kwrite(ptr2, path, len);
    
    if (kexecute(ksym_vnode_lookup + kaslr_slide, ptr2, flags, ptr, vfs_context, 0, 0, 0)) {
        return -1;
    }
    *vnode = kread64(ptr);
    kfree(ptr2, len);
    kfree(ptr, 8);
    return 0;
}

uint64_t get_vfs_context() {
    return zm_fix_addr(kexecute(ksym_vfs_current_context + kaslr_slide, 1, 0, 0, 0, 0, 0, 0));
}

int vnode_put(uint64_t vnode) {
    return kexecute(ksym_vnode_put + kaslr_slide, vnode, 0, 0, 0, 0, 0, 0);
}

unsigned int init_offsets() {

    //find symbols
    ksym_vnode_lookup = find_symbol("_vnode_lookup", false);
    ksym_vfs_current_context = find_symbol("_vfs_context_current", false);
    ksym_vnode_put = find_symbol("_vnode_put", false);
    vfs_current_context = get_vfs_context();
    
    if (ksym_vnode_lookup && ksym_vfs_current_context && ksym_vnode_put && vfs_current_context) return 0;
    return -1;
}
