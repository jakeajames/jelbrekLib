// iOS 11 moves OFVariables to const
// https://twitter.com/s1guza/status/908790514178301952
// however, if we:
//  1) Can find IODTNVRAM service
//  2) Have tfp0 / kernel read|write|alloc
//  3) Can leak kernel address of mach port
// then we can fake vtable on IODTNVRAM object
// async_wake satisfies those requirements
// however, I wasn't able to actually set or get ANY nvram variable
// not even userread/userwrite
// Guess sandboxing won't let to access nvram

#import <stdlib.h>
#import <CoreFoundation/CoreFoundation.h>
#import "kernel_utils.h"
#import "offsetof.h"
#import "offsets.h"

// convertPropToObject calls getOFVariableType
// open convertPropToObject, look for first vtable call -- that'd be getOFVariableType
// find xrefs, figure out vtable start from that
// following are offsets of entries in vtable

// it always returns false
const uint64_t searchNVRAMProperty = 0x590;
// 0 corresponds to root only
const uint64_t getOFVariablePerm = 0x558;

typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
extern const mach_port_t kIOMasterPortDefault;
CFMutableDictionaryRef IOServiceMatching(const char *name) CF_RETURNS_RETAINED;
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching CF_RELEASES_ARGUMENT);


// get kernel address of IODTNVRAM object
uint64_t get_iodtnvram_obj(void) {
    // get user serv
    io_service_t IODTNVRAMSrv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    
    // leak user serv
    uint64_t nvram_up = FindPortAddress(IODTNVRAMSrv);
    // get kern obj -- IODTNVRAM*
    uint64_t IODTNVRAMObj = KernelRead_64bits(nvram_up + off_ip_kobject);
    
    return IODTNVRAMObj;
}

uint64_t orig_vtable = -1;

void unlocknvram(void) {

    uint64_t IODTNVRAMObj = get_iodtnvram_obj();
    if (IODTNVRAMObj == 0) {
        printf("[-] get_iodtnvram_obj failed!\n");
        return;
    }
    
    uint64_t vtable_start = KernelRead_64bits(IODTNVRAMObj);
    
    orig_vtable = vtable_start;
    
    uint64_t vtable_end = vtable_start;
    // Is vtable really guaranteed to end with 0 or was it just a coincidence?..
    // should we just use some max value instead?
    while (KernelRead_64bits(vtable_end) != 0) vtable_end += sizeof(uint64_t);
    
    uint32_t vtable_len = (uint32_t) (vtable_end - vtable_start);
    
    // copy vtable to userspace
    uint64_t *buf = calloc(1, vtable_len);
    KernelRead(vtable_start, buf, vtable_len);
    
    // alter it
    buf[getOFVariablePerm/sizeof(uint64_t)] = buf[searchNVRAMProperty/sizeof(uint64_t)];
    
    // allocate buffer in kernel and copy it back
    uint64_t fake_vtable = Kernel_alloc_wired(vtable_len);
    KernelWrite(fake_vtable, buf, vtable_len);
    
    // replace vtable on IODTNVRAM object
    KernelWrite_64bits(IODTNVRAMObj, fake_vtable);
    
    free(buf);
}

int locknvram(void) {
    if (orig_vtable == -1) {
        printf("[-] Trying to lock nvram, but didnt unlock first\n");
        return -1;
    }
    
    uint64_t obj = get_iodtnvram_obj();
    if (obj == 0) { // would never happen but meh
        printf("[-] get_iodtnvram_obj failed!\n");
        return -1;
    }
    
    KernelWrite_64bits(obj, orig_vtable);
    
    printf("[+] Locked nvram\n");
    return 0;
}
