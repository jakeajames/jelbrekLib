//  Comes from Electra, adapted for FAT binary support by me
//
//  amfi_utils.c
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "amfi_utils.h"
#include "kernel_utils.h"
#include "patchfinder64.h"
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CommonCrypto/CommonDigest.h>
#include <Foundation/Foundation.h>

uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

uint32_t read_magic(FILE* file, off_t offset) {
    uint32_t magic;
    fseek(file, offset, SEEK_SET);
    fread(&magic, sizeof(uint32_t), 1, file);
    return magic;
}

void *load_bytes(FILE *file, off_t offset, size_t size) {
    void *buf = calloc(1, size);
    fseek(file, offset, SEEK_SET);
    fread(buf, size, 1, file);
    return buf;
}

void getSHA256inplace(const uint8_t* code_dir, uint8_t *out) {
    if (code_dir == NULL) {
        printf("NULL passed to getSHA256inplace!\n");
        return;
    }
    uint32_t* code_dir_int = (uint32_t*)code_dir;
    
    uint32_t realsize = 0;
    for (int j = 0; j < 10; j++) {
        if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
            realsize = swap_uint32(code_dir_int[j+1]);
            code_dir += 4*j;
        }
    }
    
    CC_SHA256(code_dir, realsize, out);
}

uint8_t *getSHA256(const uint8_t* code_dir) {
    uint8_t *out = malloc(CC_SHA256_DIGEST_LENGTH);
    getSHA256inplace(code_dir, out);
    return out;
}

uint8_t *getCodeDirectory(const char* name) {
    
    FILE* fd = fopen(name, "r");
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    
    long off = 0, file_off = 0;
    int ncmds = 0;
    BOOL foundarm64 = false;
    
    if (magic == MH_MAGIC_64) { // 0xFEEDFACF
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        off = sizeof(mh64);
        ncmds = mh64.ncmds;
    }
    else if (magic == MH_MAGIC) {
        printf("[-] %s is 32bit. What are you doing here?\n", name);
        fclose(fd);
        return NULL;
    }
    else if (magic == 0xBEBAFECA) { //FAT binary magic
        
        size_t header_size = sizeof(struct fat_header);
        size_t arch_size = sizeof(struct fat_arch);
        size_t arch_off = header_size;
        
        struct fat_header *fat = (struct fat_header*)load_bytes(fd, 0, header_size);
        struct fat_arch *arch = (struct fat_arch *)load_bytes(fd, arch_off, arch_size);
        
        int n = swap_uint32(fat->nfat_arch);
        printf("[*] Binary is FAT with %d architectures\n", n);
        
        while (n-- > 0) {
            magic = read_magic(fd, swap_uint32(arch->offset));
            
            if (magic == 0xFEEDFACF) {
                printf("[*] Found arm64\n");
                foundarm64 = true;
                struct mach_header_64* mh64 = (struct mach_header_64*)load_bytes(fd, swap_uint32(arch->offset), sizeof(struct mach_header_64));
                file_off = swap_uint32(arch->offset);
                off = swap_uint32(arch->offset) + sizeof(struct mach_header_64);
                ncmds = mh64->ncmds;
                break;
            }
            
            arch_off += arch_size;
            arch = load_bytes(fd, arch_off, arch_size);
        }
        
        if (!foundarm64) { // by the end of the day there's no arm64 found
            printf("[-] No arm64? RIP\n");
            fclose(fd);
            return NULL;
        }
    }
    else {
        printf("[-] %s is not a macho! (or has foreign endianness?) (magic: %x)\n", name, magic);
        fclose(fd);
        return NULL;
    }
    
    for (int i = 0; i < ncmds; i++) {
        struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread(&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs + file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            fclose(fd);
            return cd;
        } else {
            off += cmd.cmdsize;
        }
    }
    fclose(fd);
    return NULL;
}

//from xerub
int strtail(const char *str, const char *tail)
{
    size_t lstr = strlen(str);
    size_t ltail = strlen(tail);
    if (ltail > lstr) {
        return -1;
    }
    str += lstr - ltail;
    return memcmp(str, tail, ltail);
}

int cs_validate_csblob(const uint8_t *addr, size_t length, CS_CodeDirectory **rcd, CS_GenericBlob **rentitlements) {
    uint64_t rcdptr = Kernel_alloc(sizeof(uint64_t));
    uint64_t entptr = Kernel_alloc(sizeof(uint64_t));
    
    int ret = (int)Kernel_Execute(Find_cs_validate_csblob(), (uint64_t)addr, length, rcdptr, entptr, 0, 0, 0);
    *rcd = (CS_CodeDirectory *)KernelRead_64bits(rcdptr);
    *rentitlements = (CS_GenericBlob *)KernelRead_64bits(entptr);
    
    Kernel_free(rcdptr, sizeof(uint64_t));
    Kernel_free(entptr, sizeof(uint64_t));
    
    return ret;
}

uint64_t ubc_cs_blob_allocate(vm_size_t size) {
    if (size <= 0x1ff8) {
        uint64_t size_p = Kernel_alloc(sizeof(vm_size_t));
        if (!size_p) return 0;
        KernelWrite(size_p, &size, sizeof(vm_size_t));
        
        uint64_t kall = Find_kalloc_canblock();
        if (!kall) return 0;
        
        uint64_t site = Find_cs_blob_allocate_site();
        if (!site) return 0;
        
        uint64_t alloced = Kernel_Execute(kall, size_p, 1, site, 0, 0, 0, 0);
        if (!alloced) return 0;
        
        Kernel_free(size_p, sizeof(vm_size_t));
        alloced = ZmFixAddr(alloced);
        return alloced;
    }
    else {
        uint64_t addrp = Kernel_alloc(sizeof(uint64_t));
        if (!addrp) return 0;
        
        uint64_t kernel_map = Find_kernel_map();
        if (!kernel_map) return 0;
        
        kernel_map = KernelRead_64bits(kernel_map);
        if (!kernel_map) return 0;
        
        uint64_t alloc = Find_kernel_memory_allocate();
        if (!alloc) return 0;
        
        Kernel_Execute(alloc, kernel_map, addrp, size, 0, 4, 17, 0);
        addrp = KernelRead_64bits(addrp);
        return addrp;
    }
}

void kern_free(uint64_t addr, vm_size_t size) {
    Kernel_Execute(Find_kfree(), addr, size, 0, 0, 0, 0, 0);
}

const struct cs_hash *cs_find_md(uint8_t type) {
    return (struct cs_hash *)KernelRead_64bits(Find_cs_find_md() + ((type - 1) * 8));
}

uint64_t getCodeSignatureLC(FILE *file, int64_t *machOff) {
    size_t offset = 0;
    struct load_command *cmd = NULL;
    
    // Init at this
    *machOff = -1;
    
    uint32_t *magic = load_bytes(file, offset, sizeof(uint32_t));
    int ncmds = 0;
    
    // check magic
    if (*magic != 0xFEEDFACF && *magic != 0xBEBAFECA) {
        printf("[-] File is not an arm64 or FAT macho!\n");
        free(magic);
        return 0;
    }
    
    // FAT
    if(*magic == 0xBEBAFECA) {
        
        uint32_t arch_off = sizeof(struct fat_header);
        struct fat_header *fat = (struct fat_header*)load_bytes(file, 0, sizeof(struct fat_header));
        bool foundarm64 = false;
        
        int n = ntohl(fat->nfat_arch);
        printf("[*] Binary is FAT with %d architectures\n", n);
        
        while (n-- > 0) {
            struct fat_arch *arch = (struct fat_arch *)load_bytes(file, arch_off, sizeof(struct fat_arch));
            
            if (ntohl(arch->cputype) == 0x100000c) {
                printf("[*] Found arm64\n");
                offset = ntohl(arch->offset);
                foundarm64 = true;
                free(fat);
                free(arch);
                break;
            }
            free(arch);
            arch_off += sizeof(struct fat_arch);
        }
        
        if (!foundarm64) {
            printf("[-] Binary does not have any arm64 slice\n");
            free(fat);
            free(magic);
            return 0;
        }
    }
    
    free(magic);
    
    *machOff = offset;
    
    // get macho header
    struct mach_header_64 *mh64 = load_bytes(file, offset, sizeof(struct mach_header_64));
    ncmds = mh64->ncmds;
    free(mh64);
    
    // next
    offset += sizeof(struct mach_header_64);
    
    for (int i = 0; i < ncmds; i++) {
        cmd = load_bytes(file, offset, sizeof(struct load_command));
        
        // this!
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            free(cmd);
            return offset;
        }
        
        // next
        offset += cmd->cmdsize;
        free(cmd);
    }
    
    return 0;
}
