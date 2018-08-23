#import <dlfcn.h>
#import <stdio.h>
#import <unistd.h>
#import <sys/types.h>
#import <mach/mach.h>
#import <mach-o/loader.h>
#import <mach/error.h>
#import <errno.h>
#import <stdlib.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <sys/mman.h>
#import <spawn.h>
#import <sys/stat.h>
#import <pthread.h>
#import <signal.h>
#import <mach/thread_state.h>
#import <mach/thread_status.h>
#import <mach/thread_info.h>

void* AMFIDExceptionHandler(void* arg);
int setAmfidExceptionHandler(mach_port_t amfid_task_port, void *(exceptionHandler)(void*));
uint64_t patchAMFID(void);

#pragma pack(4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
} exception_raise_request; // the bits we need at least

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
} exception_raise_reply;
#pragma pack()

#define amfid_MISValidateSignatureAndCopyInfo_import_offset 0x4150
