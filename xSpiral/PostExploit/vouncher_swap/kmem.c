#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <mach/mach.h>

#include "kmem.h"
#include "IOKit.h"
#include "offsets.h"
#include "voucher_swap/kernel_memory.h"

uint64_t task_port_kaddr = 0;
mach_port_t tfp0 = MACH_PORT_NULL;

void prepare_for_rw_with_fake_tfp0(mach_port_t fake_tfp0) {
  tfp0 = fake_tfp0;
}

void wk32(uint64_t kaddr, uint32_t val) {
    kernel_write32(kaddr, val);
}

void wk64(uint64_t kaddr, uint64_t val) {
    kernel_write64(kaddr, val);
}

uint32_t rk32(uint64_t kaddr) {
    return kernel_read32(kaddr);
}

uint64_t rk64(uint64_t kaddr) {
  uint64_t lower = rk32(kaddr);
  uint64_t higher = rk32(kaddr+4);
  uint64_t full = ((higher<<32) | lower);
  return full;
}
