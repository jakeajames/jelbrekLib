#import <stdio.h>
#import <unistd.h>
#import <sys/types.h>
#import <mach-o/loader.h>
#import <mach/error.h>
#import <errno.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <mach/vm_map.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>

#import "cs_blob.h"
#import "utils.h"

static unsigned int hash_rank(const CodeDirectory *cd);
int get_hash(const CodeDirectory* directory, uint8_t dst[CS_CDHASH_LEN]);
int parse_superblob(uint8_t *code_dir, uint8_t dst[CS_CDHASH_LEN]);
