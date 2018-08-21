#import <stdio.h>
#import <mach-o/loader.h>
#import <stdlib.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <mach/mach.h>
#import <sys/stat.h>

// Needed definitions
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);

// init function
void init_kernel_utils(mach_port_t tfp0);

// utils
uint64_t task_self_addr(void);
uint64_t ipc_space_kernel(void);
uint64_t find_port_address(mach_port_name_t port);
mach_port_t fake_host_priv(void);
void convert_port_to_task_port(mach_port_t port, uint64_t space, uint64_t task_kaddr);
void make_port_fake_task_port(mach_port_t port, uint64_t task_kaddr);

// kernel memory stuff
size_t kread(uint64_t where, void *p, size_t size);
uint32_t kread32(uint64_t where);
uint64_t kread64(uint64_t where);
size_t kwrite(uint64_t where, const void *p, size_t size);
void kwrite32(uint64_t where, uint32_t what);
void kwrite64(uint64_t where, uint64_t what);
void kmemcpy(uint64_t dest, uint64_t src, uint32_t length);
void kfree(mach_vm_address_t address, vm_size_t size);
uint64_t kalloc(vm_size_t size);
uint64_t kmem_alloc_wired(uint64_t size);

// for messing with processes
uint64_t proc_for_pid(pid_t pid);
uint64_t proc_for_name(char *nm);
unsigned int pid_for_name(char *nm);

// used to fix what kexecute returns
typedef struct {
    uint64_t prev;
    uint64_t next;
    uint64_t start;
    uint64_t end;
} kmap_hdr_t;
uint64_t zm_fix_addr(uint64_t addr);


