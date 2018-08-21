
#import "kernel_utils.h"
#import "patchfinder64.h"
#import "offsetof.h"
#import "offsets.h"
#import <sys/snapshot.h>
#import <IOKit/IOKitLib.h>
#import <stdlib.h>

int list_snapshots(const char *vol)
{
    int dirfd = open(vol, O_RDONLY, 0);
    if (dirfd < 0) {
        perror("[-] get_dirfd");
        return -1;
    }
    
    struct attrlist alist = { 0 };
    char abuf[2048];
    
    alist.commonattr = ATTR_BULK_REQUIRED;
    
    int count = fs_snapshot_list(dirfd, &alist, &abuf[0], sizeof (abuf), 0);
    if (count < 0) {
        perror("[-] fs_snapshot_list");
        return -1;
    }
    
    char *p = &abuf[0];
    for (int i = 0; i < count; i++) {
        char *field = p;
        uint32_t len = *(uint32_t *)field;
        field += sizeof (uint32_t);
        attribute_set_t attrs = *(attribute_set_t *)field;
        field += sizeof (attribute_set_t);
        
        if (attrs.commonattr & ATTR_CMN_NAME) {
            attrreference_t ar = *(attrreference_t *)field;
            char *name = field + ar.attr_dataoffset;
            field += sizeof (attrreference_t);
            (void) printf("[snapshots] %s\n", name);
        }
        
        p += len;
    }
    
    return (0);
}

char *copyBootHash() {
    io_registry_entry_t chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
    
    unsigned char buf[1024];
    uint32_t size = 1024;
    char *hash;
    
    if (chosen && chosen != -1) {
        kern_return_t ret = IORegistryEntryGetProperty(chosen, "boot-manifest-hash", (char*)buf, &size);
        IOObjectRelease(chosen);
        
        if (ret) {
            printf("[-] Unable to read boot-manifest-hash\n");
            hash = NULL;
        }
        else {
            char *result = (char*)malloc((2 * size) | 1); // even number | 1 = that number + 1, just because why not
            memset(result, 0, (2 * size) | 1);
            
            int i = 0;
            while (i < size) {
                unsigned char ch = buf[i];
                sprintf(result + 2 * i++, "%02X", ch);
            }
            printf("Hash: %s\n", result);
            hash = strdup(result);
        }
    }
    else {
        printf("[-] Unable to get IODeviceTree:/chosen port\n");
        hash = NULL;
    }
    return hash;
}

char *find_system_snapshot() {
    const char *hash = copyBootHash();
    size_t len = strlen(hash);
    char *str = (char*)malloc(len + 29);
    memset(str, 0, len + 29); //fill it up with zeros?
    if (!hash) return 0;
    sprintf(str, "com.apple.os.update-%s", hash);
    printf("[-] System snapshot: %s\n", str);
    return str;
}

int do_rename(const char *vol, const char *snap, const char *nw) {
    int dirfd = open(vol, O_RDONLY);
    if (dirfd < 0) {
        perror("open");
        return -1;
    }
    
    int ret = fs_snapshot_rename(dirfd, snap, nw, 0);
    close(dirfd);
    if (ret != 0)
        perror("fs_snapshot_rename");
    return (ret);
}

