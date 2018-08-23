#import <stdio.h>
#import <mach-o/loader.h>
#import <stdlib.h>
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <mach/mach.h>
#import <sys/stat.h>

void init_amfid_mem(mach_port_t amfid_tp);
void* AmfidRead(uint64_t addr, uint64_t len);
void AmfidWrite_8bits(uint64_t addr, uint8_t val);
void AmfidWrite_64bits(uint64_t addr, uint64_t val);
void AmfidWrite_32bits(uint64_t addr, uint32_t val);
void* AmfidRead(uint64_t addr, uint64_t len);
