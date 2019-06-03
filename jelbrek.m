#import "jelbrek.h"
#import "amfi_utils.h"

uint32_t KASLR_Slide;
uint64_t KernelBase;
mach_port_t TFP0;
NSString *newPath;

int init_jelbrek(mach_port_t tfpzero) {
    @autoreleasepool {
        printf("[*] Initializing jelbrekLib\n");
        
        if (!MACH_PORT_VALID(tfpzero)) {
            printf("[-] tfp0 port not valid\n");
            return 1;
        }
        _offsets_init(); // Ian Beer's offset struct
        
        //------- init the required variables -------//
        TFP0 = tfpzero;
        
        //---- init utilities ----//
        init_kernel_utils(TFP0); // memory stuff
        
        KernelBase = FindKernelBase();
        if (!KernelBase) {
            printf("[-] failed to find kernel base\n");
            return 2;
        }
        KASLR_Slide = (uint32_t)(KernelBase - 0xFFFFFFF007004000); // slid kernel base - kernel base = kaslr slide
        
        int ret = InitPatchfinder(KernelBase, NULL); // patchfinder
        if (ret) {
            printf("[-] Failed to initialize patchfinder\n");
            return 3;
        }
        printf("[+] Initialized patchfinder\n");
        
        uint64_t sb = unsandbox(getpid());
        
        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSError *error;
        
        // random enough
        // let's say this is ran from an unsandboxed process
        // home dir is /var/mobile/Documents
        // there's a chance a file named kernelcache is there
        // who knows what people do XD, at least I have done it
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        [formatter setDateFormat:@"dd.MM.YY:HH.mm.ss"];
        
        NSString *docs = [[[fileManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path];
        mkdir((char *)[docs UTF8String], 0777);
        newPath = [docs stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_kernelcache", [formatter stringFromDate:[NSDate date]]]];
        
        printf("[*] copying to %s\n", [newPath UTF8String]);
        
        // create a copy to be safe
        [fileManager copyItemAtPath:@"/System/Library/Caches/com.apple.kernelcaches/kernelcache" toPath:newPath error:&error];
        if (error) {
            printf("[-] Failed to copy kernelcache with error: %s\n", [[error localizedDescription] UTF8String]);
            return 4;
        }
        
        sandbox(getpid(), sb);
        
        // init
        if (initWithKernelCache((char *)[newPath UTF8String])) {
            printf("[-] Error initializing KernelSymbolFinder\n");
            return 4;
        }
        
        printf("[+] Initialized KernelSymbolFinder\n");
        unlink((char *)[newPath UTF8String]);
        
        init_Kernel_Execute(); //kernel execution
        
        return 0;
    }
}

typedef int (*kexecFunc)(uint64_t function, size_t argument_count, ...);
int init_with_kbase(mach_port_t tfpzero, uint64_t kernelBase, kexecFunc kexec) {
    @autoreleasepool {
        printf("[*] Initializing jelbrekLib\n");
        
        if (!MACH_PORT_VALID(tfpzero)) {
            printf("[-] tfp0 port not valid\n");
            return 1;
        }
        _offsets_init(); // Ian Beer's offset struct
        
        //------- init the required variables -------//
        TFP0 = tfpzero;
        
        //---- init utilities ----//
        init_kernel_utils(TFP0); // memory stuff
        
        KernelBase = kernelBase;
        if (!KernelBase) {
            printf("[-] failed to find kernel base\n");
            return 2;
        }
        KASLR_Slide = (uint32_t)(KernelBase - 0xFFFFFFF007004000); // slid kernel base - kernel base = kaslr slide
        
        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSError *error;
        
        // random enough
        // let's say this is ran from an unsandboxed process
        // home dir is /var/mobile/Documents
        // there's a chance a file named kernelcache is there
        // who knows what people do XD, at least I have done it
        NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
        [formatter setDateFormat:@"dd.MM.YY:HH.mm.ss"];
        
        NSString *docs = [[[fileManager URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path];
        mkdir((char *)[docs UTF8String], 0777);
        newPath = [docs stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_kernelcache", [formatter stringFromDate:[NSDate date]]]];
        
        printf("[*] copying to %s\n", [newPath UTF8String]);
        
        // create a copy to be safe
        [fileManager copyItemAtPath:@"/System/Library/Caches/com.apple.kernelcaches/kernelcache" toPath:newPath error:&error];
        if (error) {
            printf("[-] Failed to copy kernelcache with error: %s\n", [[error localizedDescription] UTF8String]);
            return 4;
        }
 
        // init
        if (initWithKernelCache((char *)[newPath UTF8String])) {
            printf("[-] Error initializing KernelSymbolFinder\n");
            return 4;
        }
        
        printf("[+] Initialized KernelSymbolFinder\n");
        unlink((char *)[newPath UTF8String]);
        
        int ret = InitPatchfinder(0, (char *)[[newPath stringByAppendingString:@".dec"] UTF8String]); // patchfinder
        if (ret) {
            printf("[-] Failed to initialize patchfinder\n");
            return 3;
        }
        printf("[+] Initialized patchfinder\n");
        
        kernel_exec = kexec;
        if (!kernel_exec) init_Kernel_Execute(); //kernel execution
        
        return 0;
    }
}


void term_jelbrek() {
    printf("[*] Cleaning up...\n");
    TermPatchfinder(); // free memory used by patchfinder
    term_Kernel_Execute(); // free stuff used by kexecute
    unlink((char *)[[newPath stringByAppendingString:@".dec"] UTF8String]);
}

// Adds macho binaries on the AMFI trustcache
// This basically bypasses all signature checks on that file
// kernel thinks it's "trusted"

/*
 Usage: pass a single binary or a directory for recursive patching
 Technique originally made by xerub
 theninjaprawn slightly patched it up and created a patchfinder
 */

int trustbin(const char *path) {
    
    NSMutableArray *paths = [NSMutableArray array];
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    BOOL isDir = NO;
    if (![fileManager fileExistsAtPath:@(path) isDirectory:&isDir]) {
        printf("[-] Path does not exist!\n");
        return -1;
    }
    
    NSURL *directoryURL = [NSURL URLWithString:@(path)];
    NSArray *keys = [NSArray arrayWithObject:NSURLIsDirectoryKey];
    
    if (isDir) {
        NSDirectoryEnumerator *enumerator = [fileManager
                                             enumeratorAtURL:directoryURL
                                             includingPropertiesForKeys:keys
                                             options:0
                                             errorHandler:^(NSURL *url, NSError *error) {
                                                 if (error) printf("[-] %s\n", [[error localizedDescription] UTF8String]);
                                                 return YES;
                                             }];
        
        for (NSURL *url in enumerator) {
            NSError *error;
            NSNumber *isDirectory = nil;
            if (![url getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:&error]) {
                if (error) continue;
            }
            else if (![isDirectory boolValue]) {
                
                int rv;
                int fd;
                uint8_t *p;
                off_t sz;
                struct stat st;
                uint8_t buf[16];
                
                char *fpath = strdup([[url path] UTF8String]);
                
                if (strtail(fpath, ".plist") == 0 || strtail(fpath, ".nib") == 0 || strtail(fpath, ".strings") == 0 || strtail(fpath, ".png") == 0) {
                    continue;
                }
                
                rv = lstat(fpath, &st);
                if (rv || !S_ISREG(st.st_mode) || st.st_size < 0x4000) {
                    continue;
                }
                
                fd = open(fpath, O_RDONLY);
                if (fd < 0) {
                    continue;
                }
                
                sz = read(fd, buf, sizeof(buf));
                if (sz != sizeof(buf)) {
                    close(fd);
                    continue;
                }
                if (*(uint32_t *)buf != 0xBEBAFECA && !MACHO(buf)) {
                    close(fd);
                    continue;
                }
                
                p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
                if (p == MAP_FAILED) {
                    close(fd);
                    continue;
                }
                
                [paths addObject:@(fpath)];
                printf("[*] Will trust %s\n", fpath);
                free(fpath);
            }
        }
        if ([paths count] == 0) {
            printf("[-] No files in %s passed the integrity checks!\n", path);
            return -2;
        }
    }
    else {
        printf("[*] Will trust %s\n", path);
        [paths addObject:@(path)];
        
        int rv;
        int fd;
        uint8_t *p;
        off_t sz;
        struct stat st;
        uint8_t buf[16];
        
        if (strtail(path, ".plist") == 0 || strtail(path, ".nib") == 0 || strtail(path, ".strings") == 0 || strtail(path, ".png") == 0) {
            printf("[-] Binary not an executable! Kernel doesn't like trusting data, geez\n");
            return 2;
        }
        
        rv = lstat(path, &st);
        if (rv || !S_ISREG(st.st_mode) || st.st_size < 0x4000) {
            printf("[-] Binary too big\n");
            return 3;
        }
        
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            printf("[-] Don't have permission to open file\n");
            return 4;
        }
        
        sz = read(fd, buf, sizeof(buf));
        if (sz != sizeof(buf)) {
            close(fd);
            printf("[-] Failed to read from binary\n");
            return 5;
        }
        if (*(uint32_t *)buf != 0xBEBAFECA && !MACHO(buf)) {
            close(fd);
            printf("[-] Binary not a macho!\n");
            return 6;
        }
        
        p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED) {
            close(fd);
            printf("[-] Failed to mmap file\n");
            return 7;
        }
    }
    
    uint64_t trust_chain = Find_trustcache();
    
    printf("[*] trust_chain at 0x%llx\n", trust_chain);
    
    struct trust_chain fake_chain;
    fake_chain.next = KernelRead_64bits(trust_chain);
    //((uint64_t*)fake_chain.uuid)[0] = 0xbadbabeabadbabe;
    //((uint64_t*)fake_chain.uuid)[1] = 0xbadbabeabadbabe;
    
    arc4random_buf(fake_chain.uuid, 16);

    int cnt = 0;
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    hash_t *allhash = malloc(sizeof(hash_t) * [paths count]);
    for (int i = 0; i != [paths count]; ++i) {
        uint8_t *cd = getCodeDirectory((char*)[[paths objectAtIndex:i] UTF8String]);
        if (cd != NULL) {
            getSHA256inplace(cd, hash);
            memmove(allhash[cnt], hash, sizeof(hash_t));
            ++cnt;
        }
        else {
            printf("[-] CD NULL\n");
            continue;
        }
    }
    
    fake_chain.count = cnt;
    
    size_t length = (sizeof(fake_chain) + cnt * sizeof(hash_t) + 0x3FFF) & ~0x3FFF;
    uint64_t kernel_trust = Kernel_alloc(length);
    printf("[*] allocated: 0x%zx => 0x%llx\n", length, kernel_trust);
    
    KernelWrite(kernel_trust, &fake_chain, sizeof(fake_chain));
    KernelWrite(kernel_trust + sizeof(fake_chain), allhash, cnt * sizeof(hash_t));
    
#if __arm64e__
        Kernel_Execute(Find_pmap_load_trust_cache_ppl(), kernel_trust, length, 0, 0, 0, 0, 0);
#else
        KernelWrite_64bits(trust_chain, kernel_trust);
#endif
    
    free(allhash);
    
    return 0;
}

static const char *csblob_parse_teamid(struct cs_blob *csblob) {
    const CS_CodeDirectory *cd;
    
    cd = csblob->csb_cd;
    
    if (ntohl(KernelRead_32bits((uint64_t)cd + offsetof(CS_CodeDirectory, version))) < CS_SUPPORTSTEAMID) return 0;
    if (KernelRead_32bits((uint64_t)cd + offsetof(CS_CodeDirectory, teamOffset)) == 0) return 0;
    
    const char *name = ((const char *)cd) + ntohl(KernelRead_32bits((uint64_t)cd + offsetof(CS_CodeDirectory, teamOffset)));
    return name;
}


int bypassCodeSign(const char *macho) {
    uint64_t vnode = 0, addr = 0;
    size_t blob_size = 0;
    FILE *file = NULL;
    CS_GenericBlob *buf_blob = NULL;
    struct cs_blob *blob = NULL;
    CS_CodeDirectory *rcd = NULL;
    CS_GenericBlob *rentitlements = NULL;
    
    // open
    if ((file = fopen(macho, "rb")) == NULL) {
        printf("[-] Failed to open file '%s'\n", macho);
        goto error;
    }
    
    // get vnode
    vnode = getVnodeAtPath(macho);
    if (!vnode) {
        printf("[-] Can't get vnode for file '%s'\n", macho);
        goto error;
    }
    
    // get ubc_info
    uint64_t ubc_info = KernelRead_64bits(vnode + off_v_ubcinfo);
    if (!vnode) {
        printf("[-] Can't get ubc_info for file '%s'\n", macho);
        goto error;
    }
    
    // check if a cs_blob is already loaded, in which case there would be no need to do this
    uint64_t cs_blob = KernelRead_64bits(ubc_info + off_ubcinfo_csblobs);
    if (cs_blob) {
        printf("[*] File '%s' already has a blob! Updating gen_count\n", macho);
        KernelWrite_32bits(ubc_info + 44, KernelRead_32bits(Find_cs_gen_count()));
        goto success;
    }
    
    //------ magic start here ------//
    
    // see load_code_signature()
    
    int64_t machOffset;
    uint64_t lc_cmd = getCodeSignatureLC(file, &machOffset);
    if (!lc_cmd || machOffset < 0) {
        printf("[-] Can't find LC_CODE_SIGNATURE or binary is not arm64!\n");
        goto error;
    }
    
    struct linkedit_data_command *lcp = load_bytes(file, lc_cmd, sizeof(struct linkedit_data_command));
    lcp->dataoff += machOffset;
    
    blob_size = lcp->datasize;
    addr = Kernel_alloc(blob_size);
    if (!addr) {
        printf("[-] Failed to allocate\n");
        goto error;
    }
    
    buf_blob = load_bytes(file, lcp->dataoff, lcp->datasize);
    if (!buf_blob) {
        printf("[-] Can't load blob\n");
        goto error;
    }
    
    if (KernelWrite(addr, buf_blob, lcp->datasize) != lcp->datasize) {
        printf("[-] Can't write!\n");
        goto error;
    }
    
    // ubc_cs_blob_add:
    // cs_blob_create_validated:
    
    blob = malloc(sizeof(struct cs_blob));
    blob->csb_mem_size = lcp->datasize;
    blob->csb_mem_offset = 0;
    blob->csb_mem_kaddr = addr;
    blob->csb_flags = 0;
    blob->csb_signer_type = CS_SIGNER_TYPE_UNKNOWN;
    blob->csb_platform_binary = 0;
    blob->csb_platform_path = 0;
    blob->csb_teamid = NULL;
    blob->csb_entitlements_blob = NULL;
    blob->csb_entitlements = NULL;
    blob->csb_reconstituted = false;
    
    size_t length = lcp->datasize;
    
    if (cs_validate_csblob((const uint8_t *)addr, length, &rcd, &rentitlements)) {
        printf("[-] Invalid blob\n");
        goto error;
    }
    
    const unsigned char *md_base;
    uint8_t hash[CS_HASH_MAX_SIZE];
    int md_size;
    
    uint64_t cd = (uint64_t)rcd;
    rcd = malloc(sizeof(CS_CodeDirectory));
    KernelRead(cd, rcd, sizeof(CS_CodeDirectory));
    
    uint64_t entitlements = 0;
    
    if (rentitlements) {
        entitlements = (uint64_t)rentitlements;
        rentitlements = malloc(sizeof(CS_GenericBlob));
        KernelRead(entitlements, rentitlements, sizeof(CS_GenericBlob));
    }
    
    blob->csb_cd = (const CS_CodeDirectory *)cd;
    blob->csb_entitlements_blob = (const CS_GenericBlob *)entitlements;
    blob->csb_hashtype = cs_find_md(rcd->hashType);
    
    if (blob->csb_hashtype == NULL || KernelRead_64bits((uint64_t)blob->csb_hashtype + offsetof(struct cs_hash, cs_digest_size)) > sizeof(hash)) {
        printf("[-] UNSUPPORTED TYPE. AM I SUPPOSED TO PANIC? Hmm...\n");
        sleep(2);
        printf("nah...");
        goto error;
    }
    
    blob->csb_hash_pageshift = rcd->pageSize;
    blob->csb_hash_pagesize = (1U << rcd->pageSize);
    blob->csb_hash_pagemask = blob->csb_hash_pagesize - 1;
    blob->csb_hash_firstlevel_pagesize = 0;
    blob->csb_flags = (ntohl(rcd->flags) & CS_ALLOWED_MACHO) | CS_VALID;
    blob->csb_end_offset = (((vm_offset_t)ntohl(rcd->codeLimit) + blob->csb_hash_pagemask) & ~((vm_offset_t)blob->csb_hash_pagemask));
    if((ntohl(rcd->version) >= CS_SUPPORTSSCATTER) && (ntohl(rcd->scatterOffset))) {
        const SC_Scatter *scatter = (const SC_Scatter*)
        ((const char*)rcd + ntohl(rcd->scatterOffset));
        blob->csb_start_offset = ((off_t)ntohl(scatter->base)) * blob->csb_hash_pagesize;
    } else {
        blob->csb_start_offset = 0;
    }
    
    md_base = (const unsigned char *)cd;
    md_size = ntohl(rcd->length);
    
    // BAAAAAH
    /*blob->csb_hashtype->cs_init(&mdctx);
     blob->csb_hashtype->cs_update(&mdctx, md_base, md_size);
     blob->csb_hashtype->cs_final(hash, &mdctx);*/
    
    getSHA256inplace((uint8_t *)getCodeDirectory(macho), hash); // hash is not checked. it'll work with SHA1 as well
    memcpy(blob->csb_cdhash, hash, CS_CDHASH_LEN);
    
    // end cs_blob_create_validated
    
    blob->csb_cpu_type = 0x0100000c; // assume arm64
    blob->csb_base_offset = machOffset;
    
    // vnode_check_signature:
    blob->csb_signer_type = 0;
    blob->csb_flags = 0x24000005;
    blob->csb_platform_binary = 1;
    
    // CoreTrustCheckThisBinaryPls():
    // NAAAAH HAHA BYE BYE
    // amfidCheckPls(): screw you too
    
    // end fake vnode_check_signature()
    
    // CoreTrust & amfid both returned success as you can see ^ \ssssss
    
    vm_address_t new_mem_kaddr = 0;
    vm_size_t new_mem_size = 0;
    
    CS_CodeDirectory *new_cd = NULL;
    CS_GenericBlob const *new_entitlements = NULL;
    
    // ubc_cs_reconstitute_code_signature:
    // Apple come on, why are these funcs not separate in the kernelcache but separate on XNU sources. it would have saved me so much time...
    
    vm_offset_t new_blob_addr;
    vm_size_t new_blob_size;
    vm_size_t new_cdsize;
    
    const CS_CodeDirectory *old_cd = blob->csb_cd;
    new_cdsize = htonl(KernelRead_32bits((uint64_t)old_cd + offsetof(CS_CodeDirectory, length)));
    
    new_blob_size = sizeof(CS_SuperBlob);
    new_blob_size += sizeof(CS_BlobIndex);
    new_blob_size += new_cdsize;
    
    if (blob->csb_entitlements_blob) {
        new_blob_size += sizeof(CS_BlobIndex);
        new_blob_size += ntohl(KernelRead_32bits((uint64_t)blob->csb_entitlements_blob + offsetof(CS_GenericBlob, length)));
    }
    
    new_blob_addr = ubc_cs_blob_allocate(new_blob_size);
    if (!new_blob_addr) {
        printf("[-] Can't alloc\n");
        goto error;
    }
    
    CS_SuperBlob *new_superblob = (CS_SuperBlob *)new_blob_addr;
    KernelWrite_32bits((uint64_t)new_superblob + offsetof(CS_SuperBlob, magic), htonl(CSMAGIC_EMBEDDED_SIGNATURE));
    KernelWrite_32bits((uint64_t)new_superblob + offsetof(CS_SuperBlob, length), htonl((uint32_t)new_blob_size));
    
    if (blob->csb_entitlements_blob) {
        vm_size_t ent_offset, cd_offset;
        
        cd_offset = sizeof(CS_SuperBlob) + 2 * sizeof(CS_BlobIndex);
        ent_offset = cd_offset +  new_cdsize;
        
        KernelWrite_32bits((uint64_t)new_superblob + offsetof(CS_SuperBlob, count), htonl(2));
        KernelWrite_32bits((uint64_t)new_superblob + offsetof(CS_SuperBlob, index[0].type), htonl(CSSLOT_CODEDIRECTORY));
        KernelWrite_32bits((uint64_t)new_superblob + offsetof(CS_SuperBlob, index[0].offset), htonl((uint32_t)cd_offset));
        KernelWrite_32bits((uint64_t)new_superblob + offsetof(CS_SuperBlob, index[1].type), htonl(CSSLOT_ENTITLEMENTS));
        KernelWrite_32bits((uint64_t)new_superblob + offsetof(CS_SuperBlob, index[1].offset), htonl((uint32_t)ent_offset));
        
        void *buf = malloc(ntohl(KernelRead_32bits((uint64_t)blob->csb_entitlements_blob + offsetof(CS_GenericBlob, length))));
        KernelRead((uint64_t)blob->csb_entitlements_blob, buf, ntohl(KernelRead_32bits((uint64_t)blob->csb_entitlements_blob + offsetof(CS_GenericBlob, length))));
        KernelWrite((uint64_t)(new_blob_addr + ent_offset), buf, ntohl(KernelRead_32bits((uint64_t)blob->csb_entitlements_blob + offsetof(CS_GenericBlob, length))));
        free(buf);
        
        new_cd = (CS_CodeDirectory *)(new_blob_addr + cd_offset);
    } else {
        new_cd = (CS_CodeDirectory *)new_blob_addr;
    }
    
    void *buf = malloc(new_cdsize);
    KernelRead((uint64_t)old_cd, buf, new_cdsize);
    KernelWrite((uint64_t)new_cd, buf, new_cdsize);
    free(buf);
    
    vm_size_t len = new_blob_size;
    
    CS_CodeDirectory *_cd = NULL;
    CS_GenericBlob *_entitlements = NULL;
    
    if (cs_validate_csblob((const uint8_t *)new_blob_addr, len, &_cd, &_entitlements)) {
        printf("[-] Invalid blob\n");
        Kernel_Execute(Find_kfree(), new_blob_addr, new_blob_size, 0, 0, 0, 0, 0);
        goto error;
    }
    
    new_entitlements = _entitlements;
    new_mem_size = new_blob_size;
    new_mem_kaddr = new_blob_addr;
    
    // end ubc_cs_reconstitute_code_signature
    
    Kernel_free(blob->csb_mem_kaddr, blob->csb_mem_size);
    addr = 0;
    
    blob->csb_mem_kaddr = new_mem_kaddr;
    blob->csb_mem_size = new_mem_size;
    blob->csb_cd = new_cd;
    
    if (!new_entitlements) {
        const char *newEntitlements =   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                                        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
                                        "<plist version=\"1.0\">"
                                            "<dict>"
                                                "<key>platform-application</key>"                          // we're apple made :)
                                                "<true/>"
                                                "<key>com.apple.private.security.no-container</key>"       // no container
                                                "<true/>"
                                              //"<key>com.apple.private.security.container-required</key>" // containermanagerd no crazy
                                              //"<false/>"
                                                "<key>get-task-allow</key>"                                // allow us to task_for_pid
                                                "<true/>"
                                                "<key>com.apple.private.skip-library-validation</key>"     // allow invalid libs
                                                "<true/>"
                                            "</dict>"
                                        "</plist>";
        
        CS_GenericBlob *newBlob = malloc(sizeof(CS_GenericBlob) + strlen(newEntitlements) + 1);
        if (!newBlob) {
            printf("[-] Can't alloc new entitlements\n");
            goto error;
        }
        
        newBlob->magic = ntohl(CSMAGIC_EMBEDDED_ENTITLEMENTS);
        newBlob->length = ntohl(strlen(newEntitlements) + 1);
        memcpy(newBlob->data, newEntitlements, strlen(newEntitlements) + 1);
        new_entitlements = (CS_GenericBlob *)ubc_cs_blob_allocate(sizeof(CS_GenericBlob) + strlen(newEntitlements) + 1);
        
        if (!new_entitlements) {
            printf("[-] Can't alloc new entitlements on kernel\n");
            free(blob);
            goto error;
        }
        
        KernelWrite((uint64_t)new_entitlements, newBlob, sizeof(CS_GenericBlob) + strlen(newEntitlements) + 1);
        free(newBlob);
    }
    
    blob->csb_entitlements_blob = new_entitlements;
    
    uint64_t ents = Kernel_Execute(Find_osunserializexml(), (uint64_t)new_entitlements + offsetof(CS_GenericBlob, data), 0, 0, 0, 0, 0, 0);
    if (ents) {
        ents = ZmFixAddr(ents);
        blob->csb_entitlements = (void *)ents;
        
        uint64_t OSBoolTrue = Find_OSBoolean_True();
        OSDictionary_SetItem(ents, "platform-application", OSBoolTrue);
        OSDictionary_SetItem(ents, "com.apple.private.security.no-container", OSBoolTrue);
        OSDictionary_SetItem(ents, "get-task-allow", OSBoolTrue);
        OSDictionary_SetItem(ents, "com.apple.private.skip-library-validation", OSBoolTrue);
    }
    else {
        printf("[?] Invalid entitlement blob??\n");
        goto error;
    }
    blob->csb_reconstituted = true;
    blob->csb_teamid = csblob_parse_teamid(blob);
    
    off_t blob_start_offset = blob->csb_base_offset + blob->csb_start_offset;
    off_t blob_end_offset = blob->csb_base_offset + blob->csb_end_offset;
    
    if (blob_start_offset >= blob_end_offset || blob_start_offset < 0 || blob_end_offset <= 0) {
        printf("[-] Invalid blob\n");
        goto error;
    }
    
    // memory_object_signed()
    uint64_t ui_control = KernelRead_64bits(ubc_info + 8);
    uint64_t moc_object = KernelRead_64bits(ui_control + 8);
    KernelWrite_32bits(moc_object + 168, (KernelRead_32bits(moc_object + 168) & 0xFFFFFEFF) | (1 << 8));
    KernelWrite_32bits(ubc_info + 44, KernelRead_32bits(Find_cs_gen_count()));
    blob->csb_next = 0;
    
    // write it!
    uint64_t kblob = ubc_cs_blob_allocate(sizeof(struct cs_blob));
    KernelWrite(kblob, blob, sizeof(struct cs_blob));
    KernelWrite_64bits(ubc_info + off_ubcinfo_csblobs, kblob);
    
    if (strstr(macho, ".dylib")) {
        uint32_t v_flags = KernelRead_32bits(vnode + off_v_flags);
        KernelWrite_32bits(vnode + off_v_flags, v_flags | 0x200); // VSHARED_DYLD
    }
    
    printf("[?] Am I still alive?\n");
    goto success;
    
    //------ magic end here ------//
    
error:;
    if (file) fclose(file);
    if (vnode) vnode_put(vnode);
    if (addr) Kernel_Execute(Find_kfree(), addr, blob_size, 0, 0, 0, 0, 0);
    if (blob) free(blob);
    if (buf_blob) free(buf_blob);
    if (rcd) free(rcd);
    if (rentitlements) free(rentitlements);
    
    printf("[-] Blob creation failed!\n");
    return -1;
    
success:;
    if (file) fclose(file);
    if (vnode) vnode_put(vnode);
    if (addr) Kernel_Execute(Find_kfree(), addr, blob_size, 0, 0, 0, 0, 0);
    if (blob) free(blob);
    if (buf_blob) free(buf_blob);
    if (rcd) free(rcd);
    if (rentitlements) free(rentitlements);
    
    printf("[+] Seems like we succeeded!\n");
    return 0;
}

uint64_t unsandbox(pid_t pid) {
    if (!pid) return NO;
    
    printf("[*] Unsandboxing pid %d\n", pid);
    
    uint64_t proc = proc_of_pid(pid); // pid's proccess structure on the kernel
    uint64_t ucred = KernelRead_64bits(proc + off_p_ucred); // pid credentials
    uint64_t cr_label = KernelRead_64bits(ucred + off_ucred_cr_label); // MAC label
    uint64_t orig_sb = KernelRead_64bits(cr_label + off_sandbox_slot);
    
    KernelWrite_64bits(cr_label + off_sandbox_slot /* First slot is AMFI's. so, this is second? */, 0); //get rid of sandbox by nullifying it
    
    return (KernelRead_64bits(KernelRead_64bits(ucred + off_ucred_cr_label) + off_sandbox_slot) == 0) ? orig_sb : NO;
}

BOOL sandbox(pid_t pid, uint64_t sb) {
    if (!pid) return NO;
    
    printf("[*] Sandboxing pid %d with slot at 0x%llx\n", pid, sb);
    
    uint64_t proc = proc_of_pid(pid); // pid's proccess structure on the kernel
    uint64_t ucred = KernelRead_64bits(proc + off_p_ucred); // pid credentials
    uint64_t cr_label = KernelRead_64bits(ucred + off_ucred_cr_label /* MAC label */);
    KernelWrite_64bits(cr_label + off_sandbox_slot /* First slot is AMFI's. so, this is second? */, sb);
    
    return (KernelRead_64bits(KernelRead_64bits(ucred + off_ucred_cr_label) + off_sandbox_slot) == sb) ? YES : NO;
}

BOOL setcsflags(pid_t pid) {
    if (!pid) return NO;
    
    uint64_t proc = proc_of_pid(pid);
    uint32_t csflags = KernelRead_32bits(proc + off_p_csflags);
    uint32_t newflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    KernelWrite_32bits(proc + off_p_csflags, newflags);
    
    return (KernelRead_32bits(proc + off_p_csflags) == newflags) ? YES : NO;
}

BOOL rootify(pid_t pid) {
    if (!pid) return NO;
    
    uint64_t proc = proc_of_pid(pid);
    uint64_t ucred = KernelRead_64bits(proc + off_p_ucred);
    //make everything 0 without setuid(0), pretty straightforward.
    KernelWrite_32bits(proc + off_p_uid, 0);
    KernelWrite_32bits(proc + off_p_ruid, 0);
    KernelWrite_32bits(proc + off_p_gid, 0);
    KernelWrite_32bits(proc + off_p_rgid, 0);
    KernelWrite_32bits(ucred + off_ucred_cr_uid, 0);
    KernelWrite_32bits(ucred + off_ucred_cr_ruid, 0);
    KernelWrite_32bits(ucred + off_ucred_cr_svuid, 0);
    KernelWrite_32bits(ucred + off_ucred_cr_ngroups, 1);
    KernelWrite_32bits(ucred + off_ucred_cr_groups, 0);
    KernelWrite_32bits(ucred + off_ucred_cr_rgid, 0);
    KernelWrite_32bits(ucred + off_ucred_cr_svgid, 0);
    
    return (KernelRead_32bits(proc + off_p_uid) == 0) ? YES : NO;
}

void platformize(pid_t pid) {
    if (!pid) return;
    
    uint64_t proc = proc_of_pid(pid);
    uint64_t task = KernelRead_64bits(proc + off_task);
    uint32_t t_flags = KernelRead_32bits(task + off_t_flags);
    t_flags |= 0x400; // add TF_PLATFORM flag, = 0x400
    KernelWrite_32bits(task+off_t_flags, t_flags);
    uint32_t csflags = KernelRead_32bits(proc + off_p_csflags);
    KernelWrite_32bits(proc + off_p_csflags, csflags | 0x24004001u); //patch csflags
}

BOOL entitlePidOnAMFI(pid_t pid, const char *ent, BOOL val) {
    
    if (!pid) return NO;
    
    uint64_t proc = proc_of_pid(pid);
    uint64_t ucred = KernelRead_64bits(proc + off_p_ucred);
    uint64_t cr_label = KernelRead_64bits(ucred + off_ucred_cr_label);
    uint64_t entitlements = KernelRead_64bits(cr_label + off_amfi_slot);
    
    if (OSDictionary_GetItem(entitlements, ent) == 0) {
        printf("[*] Setting Entitlements...\n");
        uint64_t entval = OSDictionary_GetItem(entitlements, ent);
        
        printf("[i] before: %s is 0x%llx\n", ent, entval);
        OSDictionary_SetItem(entitlements, ent, (val) ? Find_OSBoolean_True() : Find_OSBoolean_False());
        
        entval = OSDictionary_GetItem(entitlements, ent);
        printf("[i] after: %s is 0x%llx\n", ent, entval);
        
        return (entval) ? YES : NO;
    }
    return YES;
}

BOOL patchEntitlements(pid_t pid, const char *entitlementString) {
    
    if (!pid) return NO;
    
#define SWAP32(val) __builtin_bswap32(val)
    
    struct cs_blob *csblob = malloc(sizeof(struct cs_blob));
    CS_CodeDirectory *code_dir = malloc(sizeof(CS_CodeDirectory));
    CS_GenericBlob *blob;
    
    // our codesign blobs can be found at our vnode -> ubcinfo -> csblobs
    uint64_t proc = proc_of_pid(pid);
    uint64_t vnode = KernelRead_64bits(proc + off_p_textvp);
    uint64_t ubc_info = KernelRead_64bits(vnode + off_v_ubcinfo);
    uint64_t cs_blobs = KernelRead_64bits(ubc_info + off_ubcinfo_csblobs);
    
    // read from there into the csblob struct
    KernelRead(cs_blobs, csblob, sizeof(struct cs_blob));
    
    uint64_t codeDirAddr = (uint64_t) csblob->csb_cd;
    uint64_t entBlobAddr = (uint64_t) csblob->csb_entitlements_blob;
    
    printf("[entitlePid][*] Code directory at 0x%llx\n", codeDirAddr);
    printf("[entitlePid][*] Blob at 0x%llx\n", entBlobAddr);
    
    // read into the code directory struct
    KernelRead(codeDirAddr, code_dir, sizeof(CS_CodeDirectory));
    if (SWAP32(code_dir->magic) != CSMAGIC_CODEDIRECTORY) {
        printf("[entitlePid] Wrong magic! 0x%x != 0x%x\n", code_dir->magic, CSMAGIC_CODEDIRECTORY);
        free(code_dir);
        free(csblob);
        return NO;
    }
    
    // get length of our current blob
    // we use SWAP32 to convert big endian to little endian
    uint32_t length = SWAP32(KernelRead_32bits(entBlobAddr + offsetof(CS_GenericBlob, length)));
    if (length < 8) {
        printf("[entitlePid] Blob too small!\n");
        free(code_dir);
        free(csblob);
        return NO;
    }
    
    printf("[entitlePid][*] length = %d\n", length);
    
    // allocate space for our new blob
    blob = malloc(sizeof(CS_GenericBlob));
    
    if (!blob) {
        printf("[entitlePid][-] Ran out of memory? oops\n");
        free(code_dir);
        free(csblob);
        return NO;
    }
    
    // read that much data into the CS_GenericBlob struct
    KernelRead(entBlobAddr, blob, length);
    
    if (strlen(entitlementString) + strlen("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
                                           "<plist version=\"1.0\">\n"
                                           "<dict>\n\n</dict>\n"
                                           "</plist>\n") > strlen(blob->data)) {
        printf("[entitlePid] Sorry! You can't make the codesigning blob bigger! You have room for %lu bytes (including plist stuff)\n", strlen(blob->data));
        
        free(code_dir);
        free(csblob);
        free(blob);
        
        return NO;
        
        // experimental
        // this seems to work now
        // but panic after some time after process quits
        
        /*      printf("[entitlePid][*] Blob is bigger than what we have, getting more room\n");
         
         // calculate new length
         uint32_t newLength = (uint32_t)(4 + 4 + strlen(entitlementString) +
         strlen("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
         "<plist version=\"1.0\">\n"
         "<dict>\n\n</dict>\n"
         "</plist>\n") + 1); // magic + length + data + null terminator
         
         // update length; BIG ENDIAN
         blob->length = SWAP32(newLength);
         
         // add more space on kernel
         entBlobAddr = Kernel_alloc(newLength);
         Kernel_Execute(Find_bzero(), entBlobAddr, newLength, 0, 0, 0, 0, 0);
         
         // add old blob
         KernelWrite(entBlobAddr, blob, length);
         
         // update address
         csblob->csb_entitlements_blob = (const CS_GenericBlob *)entBlobAddr;
         KernelWrite(cs_blobs, csblob, sizeof(struct cs_blob));
         
         // update hash
         uint8_t newHash[CC_SHA256_DIGEST_LENGTH];
         CC_SHA256(blob, newLength, (unsigned char *)newHash);
         KernelWrite(codeDirAddr + SWAP32(code_dir->hashOffset) - CSSLOT_ENTITLEMENTS * code_dir->hashSize, newHash, sizeof(newHash));
         
         length = newLength;
         */
    }
    
    uint8_t entHash[CC_SHA256_DIGEST_LENGTH];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    
    // make sure actual SHA256 hash of the blob matches the one on the code directory
    KernelRead(codeDirAddr + SWAP32(code_dir->hashOffset) - CSSLOT_ENTITLEMENTS * code_dir->hashSize, entHash, sizeof(entHash));
    CC_SHA256(blob, length, digest);
    
    if (memcmp(entHash, digest, sizeof(digest))) {
        printf("[entitlePid] Original hash doesn't match?\n");
        free(blob);
        free(code_dir);
        free(csblob);
        return NO;
    }
    
    // add our new entitlements
    sprintf(blob->data,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            "<plist version=\"1.0\">\n"
            "<dict>\n%s\n</dict>\n"
            "</plist>\n", entitlementString);
    
    // calculate the SHA256
    CC_SHA256(blob, length, digest);
    
    // write our new hash
    KernelWrite(codeDirAddr + SWAP32(code_dir->hashOffset) - CSSLOT_ENTITLEMENTS * code_dir->hashSize, digest, sizeof(digest));
    
    free(code_dir);
    
    // write our new blob
    KernelWrite(entBlobAddr, blob, length);
    
    //KernelWrite_64bits((uint64_t) csblob->csb_entitlements, OSUnserializeXML(blob->data));
    
    bzero(blob, sizeof(CS_GenericBlob));
    
    // check if the entitlements are there
    int rv = csops(pid, CS_OPS_ENTITLEMENTS_BLOB, blob, length);
    if (rv) {
        printf("[entitlePid] Failed setting entitlements!\n");
        free(blob);
        free(csblob);
        return NO;
    } else {
        printf("[entitlePid] Set entitlements!\n\tNew blob: \n%s\n", blob->data);
    }
    
    // now time to patch ents on AMFI too
    uint64_t ucred = KernelRead_64bits(proc + off_p_ucred);
    uint64_t cr_label = KernelRead_64bits(ucred + off_ucred_cr_label);
    uint64_t entitlements = KernelRead_64bits(cr_label + off_amfi_slot);
    
    // Add unserialized entitlements to the AMFI slot
    uint64_t newEntitlements = OSUnserializeXML(blob->data);
    
    if (!newEntitlements) {
        printf("[entitlePid][-] Error unserializing ents\n %s\n", blob->data);
        free(blob);
        return NO;
    }
    
    printf("[entitlePid][+] Patching unserialized entitlements\n");
    KernelWrite_64bits((uint64_t)csblob->csb_entitlements, newEntitlements);
    free(csblob);
    
    printf("[entitlePid][i] New AMFI ents at 0x%llx\n", newEntitlements);
    
    printf("[entitlePid][*] Patching Entitlements on AMFI...\n");
    printf("[entitlePid][i] before: ents at 0x%llx\n", entitlements);
    
    KernelWrite_64bits(cr_label + off_amfi_slot, newEntitlements);
    entitlements = KernelRead_64bits(cr_label + off_amfi_slot);
    
    printf("[entitlePid][i] after: ents at 0x%llx\n", entitlements);
    
    free(blob);
    return (entitlements == newEntitlements) ? YES : NO;
}

uint64_t borrowCredsFromPid(pid_t target, pid_t donor) {
    uint64_t proc = proc_of_pid(target);
    uint64_t donorproc = proc_of_pid(donor);
    uint64_t cred = KernelRead_64bits(proc + off_p_ucred);
    uint64_t donorcred = KernelRead_64bits(donorproc + off_p_ucred);
    KernelWrite_64bits(proc + off_p_ucred, donorcred);
    return cred;
}

uint64_t borrowCredsFromDonor(pid_t target, char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    int rv = posix_spawn(&pd, binary, NULL, NULL, (char **)&args, env);
    if (rv) return rv;
    
    usleep(100);
    kill(pd, SIGSTOP); // suspend
    
    platformize(pd);
    uint64_t proc = proc_of_pid(target);
    uint64_t donorproc = proc_of_pid(pd);
    uint64_t cred = KernelRead_64bits(proc + off_p_ucred);
    uint64_t donorcred = KernelRead_64bits(donorproc + off_p_ucred);
    KernelWrite_64bits(proc + off_p_ucred, donorcred);
    
    return cred;
}

void undoCredDonation(pid_t target, uint64_t origcred) {
    uint64_t proc = proc_of_pid(target);
    KernelWrite_64bits(proc + off_p_ucred, origcred);
}

int launchAsPlatform(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED); //this flag will make the created process stay frozen until we send the CONT signal. This so we can platformize it before it launches.
    
    int rv = posix_spawn(&pd, binary, NULL, &attr, (char **)&args, env);
    if (rv) return rv;
    
    platformize(pd);
    
    kill(pd, SIGCONT); //continue
    
    int a = 0;
    waitpid(pd, &a, 0);
    
    return WEXITSTATUS(a);
}

int launchSuspended(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED); //this flag will make the created process stay frozen until we send the CONT signal.
    
    int rv = posix_spawn(&pd, binary, NULL, &attr, (char **)&args, env);
    
    if (rv) return rv;
    else return pd;
}

int launch(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    int rv = posix_spawn(&pd, binary, NULL, NULL, (char **)&args, env);
    if (rv) return rv;
    
    return 0;
    
    //int a = 0;
    //waitpid(pd, &a, 0);
    
    //return WEXITSTATUS(a);
}

BOOL remount1126() {
    uint64_t rootfs_vnode = getVnodeAtPath("/");
    printf("\n[*] vnode of /: 0x%llx\n", rootfs_vnode);
    uint64_t v_mount = KernelRead_64bits(rootfs_vnode + off_v_mount);
    uint32_t v_flag = KernelRead_32bits(v_mount + off_mnt_flag);
    printf("[*] Removing RDONLY, NOSUID and ROOTFS flags\n");
    printf("[*] Flags before 0x%x\n", v_flag);
    v_flag &= ~MNT_NOSUID;
    v_flag &= ~MNT_RDONLY;
    v_flag &= ~MNT_ROOTFS;
    
    printf("[*] Flags now 0x%x\n", v_flag);
    KernelWrite_32bits(v_mount + off_mnt_flag, v_flag);
    
    char *nmz = strdup("/dev/disk0s1s1");
    int rv = mount("apfs", "/", MNT_UPDATE, (void *)&nmz);
    free(nmz);
    
    printf("[*] Remounting /, return value = %d\n", rv);
    
    v_mount = KernelRead_64bits(rootfs_vnode + off_v_mount);
    KernelWrite_32bits(v_mount + off_mnt_flag, v_flag);
    
    int fd = open("/RWTEST", O_RDONLY);
    if (fd == -1) {
        fd = creat("/RWTEST", 0777);
    } else {
        printf("[-] File already exists!\n");
    }
    close(fd);
    printf("[?] Did we mount / as read+write? %s\n", [[NSFileManager defaultManager] fileExistsAtPath:@"/RWTEST"] ? "yes" : "no");
    
    return [[NSFileManager defaultManager] fileExistsAtPath:@"/RWTEST"] ? YES : NO;
}

int mountDevAtPathAsRW(const char* devpath, const char* path) {
    struct hfs_mount_args mntargs;
    bzero(&mntargs, sizeof(struct hfs_mount_args));
    mntargs.fspec = (char*)devpath;
    mntargs.hfs_mask = 1;
    gettimeofday(NULL, &mntargs.hfs_timezone);
    
    int rvtmp = mount("apfs", path, 0, (void *)&mntargs);
    printf("[*] mounting: %d\n", rvtmp);
    return rvtmp;
}

// originally found by umanghere
// reversed from Electra back when it was closed source
int remountRootFS() {
    
    int rv = -1, ret = -1;
    // snapshot methods only work if we pass a real mount point. With a snapshot, they fail. That's how we tell if this has already ran
    
    if (kCFCoreFoundationVersionNumber > 1451.51 && list_snapshots("/")) { //the second check makes it only run once
        
        uint64_t devVnode = getVnodeAtPath("/dev/disk0s1s1");
        uint64_t specinfo = KernelRead_64bits(devVnode + off_v_specinfo);
        
        // clear specflags in order to be able to mount twice
        KernelWrite_32bits(specinfo + off_specflags, 0);
        
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/rootfsmnt"])
            rmdir("/var/rootfsmnt");
        
        mkdir("/var/rootfsmnt", 0777);
        chown("/var/rootfsmnt", 0, 0);
        
        // get kernel creds to bypass sandbox checks when mounting in /var
        printf("[*] Temporarily setting kernel credentials\n");
        uint64_t creds = borrowCredsFromPid(getpid(), 0);
        
        // Mount /dev/disk0s1s1 as read & write on /var/rootfsmnt
        // this is so we can use do_rename to work with the snapshot corresponding to that device
        // remember? we can't pass / to it as it's a snapshot by itself
        
        if (mountDevAtPathAsRW("/dev/disk0s1s1", "/var/rootfsmnt")) {
            printf("[-] Error mounting root at %s\n", "/var/rootfsmnt");
        }
        else {
            printf("[*] Disabling the APFS snapshot mitigations\n");
            char *snap = find_system_snapshot();
            // rename the snapshot to "orig-fs" so the system can't find it and resets back to /dev/disk0s1s1 on next boot
            if (snap && !do_rename("/var/rootfsmnt", snap, "orig-fs")) {
                // clean up
                rv = 0;
                unmount("/var/rootfsmnt", 0);
                rmdir("/var/rootfsmnt");
            }
        }
        
        printf("[*] Restoring our credentials\n");
        undoCredDonation(getpid(), creds);
        vnode_put(devVnode);
        
        if (rv) {
            printf("[-] Failed to disable the APFS snapshot mitigations\n");
        }
        else {
            printf("[*] Disabled the APFS snapshot mitigations\n");
            printf("[*] Restarting\n");
            sleep(2);
            // restart so changes take effect
            // do that by killing launchd. lazy but effective method
            kill(1, SIGKILL);
        }
        ret = -1;
    }
    else {
        ret = 0;
        remount1126(); // now we can use a normal mount patch!
    }
    return ret;
}

uint64_t getVnodeAtPath(const char *path) {
    uint64_t *vnode_ptr = (uint64_t *)malloc(8);
    if (vnode_lookup(path, 0, vnode_ptr, get_vfs_context())) {
        printf("[-] unable to get vnode from path for %s\n", path);
        free(vnode_ptr);
        return -1;
    }
    else {
        uint64_t vnode = *vnode_ptr;
        free(vnode_ptr);
        return vnode;
    }
}

// https://gist.github.com/ccbrown/9722406
void HexDump(uint64_t addr, size_t size) {
    void *data = malloc(size);
    KernelRead(addr, data, size);
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
    free(data);
}

BOOL PatchHostPriv(mach_port_t host) {
    
#define IO_ACTIVE 0x80000000
#define IKOT_HOST_PRIV 4
    
    // locate port in kernel
    uint64_t host_kaddr = FindPortAddress(host);
    
    // change port host type
    uint32_t old = KernelRead_32bits(host_kaddr + 0x0);
    printf("[-] Old host type: 0x%x\n", old);
    
    KernelWrite_32bits(host_kaddr + 0x0, IO_ACTIVE | IKOT_HOST_PRIV);
    
    uint32_t new = KernelRead_32bits(host_kaddr);
    printf("[-] New host type: 0x%x\n", new);
    
    return ((IO_ACTIVE | IKOT_HOST_PRIV) == new) ? YES : NO;
}

BOOL hidePath(char *path) {
    // for you all jailbreak-detection-ers
    // your time is over
    // say hello to this guy
    
#define VISSHADOW 0x008000
    
    uint64_t vnode = getVnodeAtPath(path);
    if (vnode == -1) {
        printf("[-] Unable to hide path: %s\n", path);
        return NO;
    }
    uint32_t v_flags = KernelRead_32bits(vnode + off_v_flags);
    KernelWrite_32bits(vnode + off_v_flags, v_flags | VISSHADOW);
    
    return ![[NSFileManager defaultManager] fileExistsAtPath:@(path)];
}

BOOL fixMmap(char *path) {
    // for you all sandbox-blocked-mmap-ers
    // it's your time to get freedom
    // say hello to this guy
    
#define VSHARED_DYLD 0x000200
    
    uint64_t vnode = getVnodeAtPath(path);
    if (vnode == -1) {
        printf("[-] Unable to fix mmap of path: %s\n", path);
        return NO;
    }
    uint32_t v_flags = KernelRead_32bits(vnode + off_v_flags);
    KernelWrite_32bits(vnode + off_v_flags, v_flags | VSHARED_DYLD);
    
    vnode_put(vnode);
    
    return KernelRead_32bits(vnode + off_v_flags) & VSHARED_DYLD;
}

/*int addSandboxExtension() {
 
 }*/
