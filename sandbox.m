#import "jelbrek.h"
#import "sandbox.h"

// defines
#define EXT_TABLE_SIZE 9
#define RET_ERR 0xC
#define RET_OK  0x0

// structures
struct extension_hdr {
    extension_hdr_t next;
    const char *desc;
    extension_t ext_lst;
};

struct extension {
    extension_t next;
    uint64_t desc;
    uint64_t ext_list;
    uint8_t something[32];
    uint32_t type;
    uint32_t subtype;
    void *data;
    uint64_t data_len;
    uint64_t unk0;
    uint64_t unk1;
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

// get 64 higher bits of 64bit int multiplication
// https://stackoverflow.com/a/28904636
uint64_t mulhi(uint64_t a, uint64_t b) {
    uint64_t    a_lo = (uint32_t)a;
    uint64_t    a_hi = a >> 32;
    uint64_t    b_lo = (uint32_t)b;
    uint64_t    b_hi = b >> 32;
    
    uint64_t    a_x_b_hi =  a_hi * b_hi;
    uint64_t    a_x_b_mid = a_hi * b_lo;
    uint64_t    b_x_a_mid = b_hi * a_lo;
    uint64_t    a_x_b_lo =  a_lo * b_lo;
    
    uint64_t    carry_bit = ((uint64_t)(uint32_t)a_x_b_mid +
                             (uint64_t)(uint32_t)b_x_a_mid +
                             (a_x_b_lo >> 32) ) >> 32;
    
    uint64_t    multhi = a_x_b_hi +
    (a_x_b_mid >> 32) + (b_x_a_mid >> 32) +
    carry_bit;
    
    return multhi;
}

int hashingMagic(const char *desc) {
    // inlined into exception_add
    uint64_t hashed = 0x1505;
    
    // if desc == NULL, then returned value would be 8
    // APPL optimizes it for some reason
    // but meh, desc should never be NULL or you get
    // null dereference in exception_add
    // if (desc == NULL) return 8;
    
    if (desc != NULL) {
        for (const char* dp = desc; *dp != '\0'; ++dp) {
            hashed += hashed << 5;
            hashed += (int64_t) *dp;
        }
    }
    
    uint64_t magic = 0xe38e38e38e38e38f;
    
    uint64_t hi = mulhi(hashed, magic);
    hi >>= 3;
    hi = (hi<<3) + hi;
    
    hashed -= hi;
    
    return (int)hashed;
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
        
        KernelWrite(ext_p, &ext, sizeof(ext));
    } else {
        printf("[-] Failed to create sandbox extension\n");
    }
    
    return ext_p;
}

uint64_t make_ext_hdr(const char* key, uint64_t ext_lst) {
    struct extension_hdr hdr;
    
    uint64_t khdr = smalloc(sizeof(hdr));
    
    if (khdr) {
        // we add headers to end
        hdr.next = 0;
        hdr.desc = (char *)sstrdup(key);
        if (hdr.desc == 0) {
            printf("[-] Failed to create add key in sandbox extension\n");
            return 0;
        }
        
        hdr.ext_lst = (extension_t)ext_lst;
        KernelWrite(khdr, &hdr, sizeof(hdr));
    }
    
    return khdr;
}

void extension_add(uint64_t ext, uint64_t sb, const char* ent_key) {
    // XXX patchfinder + kexecute would be way better
    
    int slot = hashingMagic(ent_key);
    uint64_t insert_at_p = sb + sizeof(void*) + slot * sizeof(void*);
    uint64_t insert_at = KernelRead_64bits(insert_at_p);
    
    while (insert_at != 0) {
        uint64_t kdsc = KernelRead_64bits(insert_at + offsetof(struct extension_hdr, desc));
        
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
    uint64_t insert_at_p = sb + sizeof(void*) + slot * sizeof(void*);
    uint64_t insert_at = KernelRead_64bits(insert_at_p);
    
    while (insert_at != 0) {
        uint64_t kdsc = KernelRead_64bits(insert_at + offsetof(struct extension_hdr, desc));
        
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
    if (hasFileExtension(sandbox, "/Library", ent_key)) {
        printf("[sbex][i] Pid %d already has '%s', skipping\n", pid, "/Library");
    }
    return (ext != 0);
}
