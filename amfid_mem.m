#import "amfid_mem.h"
#import "kernel_utils.h"

#import <Foundation/Foundation.h>

static mach_port_t amfid_task_port;

void init_amfid_mem(mach_port_t amfid_tp) {
    amfid_task_port = amfid_tp;
}

void* AmfidRead(uint64_t addr, uint64_t len) {
    kern_return_t ret;
    vm_offset_t buf = 0;
    mach_msg_type_number_t num = 0;
    ret = mach_vm_read(amfid_task_port, addr, len, &buf, &num);
    
    if (ret != KERN_SUCCESS) {
        printf("[-] amfid read failed (0x%llx)\n", addr);
        return NULL;
    }
    uint8_t* outbuf = malloc(len);
    memcpy(outbuf, (void*)buf, len);
    mach_vm_deallocate(mach_task_self(), buf, num);
    return outbuf;
}

void AmfidWrite_8bits(uint64_t addr, uint8_t val) {
    kern_return_t err = mach_vm_write(amfid_task_port, addr, (vm_offset_t)&val, 1);
    if (err != KERN_SUCCESS) {
        printf("[-] amfid write failed (0x%llx)\n", addr);
    }
}

void AmfidWrite_32bits(uint64_t addr, uint32_t val) {
    kern_return_t err = mach_vm_write(amfid_task_port, addr, (vm_offset_t)&val, 4);
    if (err != KERN_SUCCESS) {
        printf("[-] amfid write failed (0x%llx)\n", addr);
    }
}


void AmfidWrite_64bits(uint64_t addr, uint64_t val) {
    kern_return_t err = mach_vm_write(amfid_task_port, addr, (vm_offset_t)&val, 8);
    if (err != KERN_SUCCESS) {
        printf("[-] amfid write failed (0x%llx)\n", addr);
    }
}

