#import "jelbrek.h"
#import "sandbox.h"

// defines
#define EXT_TABLE_SIZE 9
#define RET_ERR 0xC
#define RET_OK  0x0

// structures
struct extension_hdr {
    extension_hdr_t next;
    extension_t ext_lst;
    char desc[];
};

struct extension {
    extension_t next;           // 0: 0x0000000000000000;
    uint64_t desc;              // 8: 0xffffffffffffffff;
    uint8_t something[20];      // 16: all zero
    uint16_t num;               // 36: 1
    uint8_t type;               // 38: -
    uint8_t num3;               // 39: 0
    uint32_t subtype;           // 40: -
    uint32_t num4;              // 44: -
    void* data;                 // 48: -
    uint64_t data_len;          // 56: -
    uint16_t num5;              // 64: 0 for files
    uint8_t something_2[14];    // 66: -
    uint64_t ptr3;              // 80: 0 for files
    uint64_t ptr4;              // 88: -
    // 96: END OF STRUCT
};

// utils
uint64_t smalloc(uint64_t size) {
    uint64_t ret = Kernel_Execute(Find_smalloc(), size, 0, 0, 0, 0, 0, 0);
    return (ret) ? ZmFixAddr(ret) : ret;
}

uint64_t sstrdup(const char* s) {
    size_t slen = strlen(s) + 1;
    
    uint64_t ks = smalloc(slen);
    if (ks) {
        KernelWrite(ks, s, slen);
    }
    
    return ks;
}

unsigned int hashingMagic(const char *desc) {
    //size_t keyLen = strlen(desc);
    unsigned int hashed;
    char ch, ch2;
    char *chp;
    
    ch = *desc;
    
    if (*desc) {
        chp = (char *)(desc + 1);
        hashed = 0x1505;
        
        do {
            hashed = 33 * hashed + ch;
            ch2 = *chp++;
            ch = ch2;
        }
        while (ch2);
    }
    else hashed = 0x1505;
    
    return hashed % 9;
}

// actual sandbox stuff
uint64_t createFileExtension(const char* path, uint64_t nextptr) {
    size_t slen = strlen(path);
    
    if (path[slen - 1] == '/') {
        fprintf(stderr, "[-] No traling slash in path pls\n");
        return 0;
    }
    
    uint64_t ext_p = smalloc(sizeof(struct extension));
    uint64_t ks = sstrdup(path);
    
    if (ext_p && ks) {
        struct extension ext;
        bzero(&ext, sizeof(ext));
        ext.next = (extension_t)nextptr;
        ext.desc = 0xffffffffffffffff;
        
        ext.type = ET_FILE;
        ext.subtype = 0;
        
        ext.data = (void*)ks;
        ext.data_len = slen;
        
        ext.num = 1;
        ext.num3 = 1;
        
        KernelWrite(ext_p, &ext, sizeof(ext));
    } else {
        printf("[-] Failed to create sandbox extension\n");
    }
    
    return ext_p;
}

uint64_t make_ext_hdr(const char* key, uint64_t ext_lst) {
    struct extension_hdr hdr;
    
    uint64_t khdr = smalloc(sizeof(hdr) + strlen(key) + 1);
    
    if (khdr) {
        // we add headers to end
        hdr.next = 0;
        hdr.ext_lst = (extension_t)ext_lst;
        
        KernelWrite(khdr, &hdr, sizeof(hdr));
        KernelWrite(khdr + offsetof(struct extension_hdr, desc), key, strlen(key) + 1);
    }
    
    return khdr;
}

void extension_add(uint64_t ext, uint64_t sb, const char* ent_key) {
    // XXX patchfinder + kexecute would be way better
    
    int slot = hashingMagic(ent_key);
    uint64_t ext_table = KernelRead_64bits(sb + 8);
    uint64_t insert_at_p = ext_table + slot * 8;
    uint64_t insert_at = KernelRead_64bits(insert_at_p);
    
    while (insert_at != 0) {
        uint64_t kdsc = insert_at + offsetof(struct extension_hdr, desc);
        
        if (Kernel_strcmp(kdsc, ent_key) == 0) {
            break;
        }
        
        insert_at_p = insert_at;
        insert_at = KernelRead_64bits(insert_at);
    }
    
    if (insert_at == 0) {
        insert_at = make_ext_hdr(ent_key, ext);
        KernelWrite_64bits(insert_at_p, insert_at);
    } else {
        // XXX no duplicate check
        uint64_t ext_lst_p = insert_at + offsetof(struct extension_hdr, ext_lst);
        uint64_t ext_lst = KernelRead_64bits(ext_lst_p);
        
        while (ext_lst != 0) {
            fprintf(stderr, "[-] ext_lst_p = 0x%llx ext_lst = 0x%llx\n", ext_lst_p, ext_lst);
            ext_lst_p = ext_lst + offsetof(struct extension, next);
            ext_lst = KernelRead_64bits(ext_lst_p);
        }
        
        fprintf(stderr, "[-] ext_lst_p = 0x%llx ext_lst = 0x%llx\n", ext_lst_p, ext_lst);
        
        KernelWrite_64bits(ext_lst_p, ext);
    }
}

bool hasFileExtension(uint64_t sb, const char* path, char *ent_key) {
    const char* desc = ent_key;
    bool found = 0;
    
    int slot = hashingMagic(ent_key);
    uint64_t ext_table = KernelRead_64bits(sb + 8);
    uint64_t insert_at_p = ext_table + slot * 8;
    uint64_t insert_at = KernelRead_64bits(insert_at_p);
    
    while (insert_at != 0) {
        uint64_t kdsc = insert_at + offsetof(struct extension_hdr, desc);
        
        if (Kernel_strcmp(kdsc, desc) == 0) {
            break;
        }
        
        insert_at_p = insert_at;
        insert_at = KernelRead_64bits(insert_at);
    }
    
    if (insert_at != 0) {
        uint64_t ext_lst = KernelRead_64bits(insert_at + offsetof(struct extension_hdr, ext_lst));
        
        uint64_t plen = strlen(path);
        char *exist = malloc(plen + 1);
        exist[plen] = '\0';
        
        while (ext_lst != 0) {
            
            uint64_t data_len = KernelRead_64bits(ext_lst + offsetof(struct extension, data_len));
            if (data_len == plen) {
                uint64_t data = KernelRead_64bits(ext_lst + offsetof(struct extension, data));
                KernelRead(data, exist, plen);
                
                if (!strcmp(path, exist)) {
                    found = 1;
                    break;
                }
            }
            ext_lst = KernelRead_64bits(ext_lst);
        }
        free(exist);
    }
    
    return found;
}

bool addSandboxExceptionsToPid(pid_t pid, char *ent_key, char **paths) {
    uint64_t proc = proc_of_pid(pid);
    uint64_t ucred = KernelRead_64bits(proc + off_p_ucred);
    uint64_t cr_label = KernelRead_64bits(ucred + off_ucred_cr_label);
    uint64_t sandbox = KernelRead_64bits(cr_label + off_sandbox_slot);
    
    if (!sandbox) {
        printf("[sbex][i] Pid %d is not sandboxed!\n", pid);
        return YES;
    }
    
    uint64_t ext = 0;

    while (*paths) {
        if (hasFileExtension(sandbox, *paths, ent_key)) {
            printf("[sbex][i] Pid %d already has '%s', skipping\n", pid, *paths);
            ++paths;
            continue;
        }
        
        printf("[sbex][i] Adding '%s' file extension for key '%s'\n", *paths, ent_key);
        ext = createFileExtension(*paths, ext);
        if (ext == 0) {
            printf("[sbex][-] Adding (%s) failed, panic!\n", *paths);
        }
        ++paths;
    }
    
    if (ext != 0) {
        printf("[sbex][i] Adding exceptions on pid %d's sandbox\n", pid);
        extension_add(ext, sandbox, ent_key);
    }
    return (ext != 0);
}
