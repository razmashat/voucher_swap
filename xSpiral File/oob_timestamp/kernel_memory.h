/*
 * kernel_memory.h
 * Brandon Azad
 */
#ifndef OOB_TIMESTAMP__KERNEL_MEMORY__H_
#define OOB_TIMESTAMP__KERNEL_MEMORY__H_

#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef KERNEL_MEMORY_EXTERN
#define extern KERNEL_MEMORY_EXTERN
#endif

/*
 * kernel_task_port
 *
 * Description:
 * 	The kernel task port.
 */
extern mach_port_t kernel_task_port;

/*
 * kernel_vm_allocate
 *
 * Description:
 * 	Allocate kernel virtual memory with mach_vm_allocate().
 */
uint64_t kernel_vm_allocate(size_t size);

/*
 * kernel_vm_deallocate
 *
 * Description:
 * 	Deallocate kernel virtual memory with mach_vm_deallocate().
 */
void kernel_vm_deallocate(uint64_t address, size_t size);

/*
 * kernel_vm_protect
 *
 * Description:
 * 	Set permissions on kernel virtual memory with mach_vm_protect().
 */
bool kernel_vm_protect(uint64_t address, size_t size, vm_prot_t prot);

/*
 * kernel_vm_remap
 *
 * Description:
 * 	Remap kernel memory into userspace. The address and size must be page-aligned.
 */
void *kernel_vm_remap(uint64_t address, size_t size);

/*
 * kernel_read
 *
 * Description:
 * 	Read data from kernel memory.
 */
bool kernel_read(uint64_t address, void *data, size_t size);

/*
 * kernel_write
 *
 * Description:
 * 	Write data to kernel memory.
 */
bool kernel_write(uint64_t address, const void *data, size_t size);

/*
 * kernel_read8
 *
 * Description:
 * 	Read a single byte from kernel memory. If the read fails, -1 is returned.
 */
uint8_t kernel_read8(uint64_t address);

/*
 * kernel_read16
 *
 * Description:
 * 	Read a 16-bit value from kernel memory. If the read fails, -1 is returned.
 */
uint16_t kernel_read16(uint64_t address);

/*
 * kernel_read32
 *
 * Description:
 * 	Read a 32-bit value from kernel memory. If the read fails, -1 is returned.
 */
uint32_t kernel_read32(uint64_t address);

/*
 * kernel_read64
 *
 * Description:
 * 	Read a 64-bit value from kernel memory. If the read fails, -1 is returned.
 */
uint64_t kernel_read64(uint64_t address);

/*
 * kernel_write8
 *
 * Description:
 * 	Write a single byte to kernel memory.
 */
bool kernel_write8(uint64_t address, uint8_t value);

/*
 * kernel_write16
 *
 * Description:
 * 	Write a 16-bit value to kernel memory.
 */
bool kernel_write16(uint64_t address, uint16_t value);

/*
 * kernel_write32
 *
 * Description:
 * 	Write a 32-bit value to kernel memory.
 */
bool kernel_write32(uint64_t address, uint32_t value);

/*
 * kernel_write64
 *
 * Description:
 * 	Write a 64-bit value to kernel memory.
 */
bool kernel_write64(uint64_t address, uint64_t value);

#undef extern

#endif
