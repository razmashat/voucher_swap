//
//  noncereboot.c
//  noncereboot1131UI
//
//  Created by Pwn20wnd on 6/30/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#include "noncereboot.h"
#include <mach/mach.h>
#include "kmem.h"
#include "kutils.h"
#include "patchfinder64.h"
#include "kexecute.h"
#include "user_client.h"

mach_port_t tfpzero = MACH_PORT_NULL;

int start_noncereboot(mach_port_t tfp0) {
    printf("Starting noncereboot1131...\n");
    
    int err = ERR_NOERR;
    
    if (tfp0 == MACH_PORT_NULL) {
        return ERR_TFP0;
    }
    
    tfpzero = tfp0;

    // Get the slide
    uint64_t slide = get_kaslr_slide();
    printf("slide: 0x%016llx\n", slide);
    
    uint64_t kernel_base = slide + 0xFFFFFFF007004000;
    
    // Loads the kernel into the patch finder, which just fetches the kernel memory for patchfinder use
    init_kernel(kernel_base, NULL);
    
    init_kexecute();
    
    // Get our and the kernels struct proc from allproc
    uint32_t our_pid = getpid();
    uint64_t our_proc = get_proc_struct_for_pid(our_pid);
    uint64_t kern_proc = get_proc_struct_for_pid(0);
    
    if (!our_proc || !kern_proc) {
        err = ERR_POST_EXPLOITATION;
        goto out;
    }
    
    printf("our proc is at 0x%016llx\n", our_proc);
    printf("kern proc is at 0x%016llx\n", kern_proc);
    
    // Properly copy the kernel's credentials so setuid(0) doesn't crash
    uint64_t field, cred;
    assume_kernel_credentials(&field, &cred);
    setuid(0);
    
out:
    term_kexecute();
    term_kernel();
    return err;
}
