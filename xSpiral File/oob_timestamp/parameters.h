/*
 * parameters.h
 * Brandon Azad
 */
#ifndef OOB_TIMESTAMP__PARAMETERS_H_
#define OOB_TIMESTAMP__PARAMETERS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef PARAMETERS_EXTERN
#define extern PARAMETERS_EXTERN
#endif

// Generate the name for an offset.
#define OFFSET(base_, object_)		_##base_##__##object_##__offset_

// Generate the name for the size of an object.
#define SIZE(object_)			_##object_##__size_

// Generate the name for the address of an object.
#define ADDRESS(object_)		_##object_##__address_

// Generate the name for the static (unslid) address of an object.
#define STATIC_ADDRESS(object_)		_##object_##__static_address_


// A convenience macro for accessing a field of a structure.
#define FIELD(object_, struct_, field_, type_)	\
	( *(type_ *) ( ((uint8_t *) object_) + OFFSET(struct_, field_) ) )

// Parameters for host.
extern size_t OFFSET(host, special);

// Parameters for ipc_entry.
extern size_t SIZE(ipc_entry);
extern size_t OFFSET(ipc_entry, ie_object);
extern size_t OFFSET(ipc_entry, ie_bits);

// Parameters for ipc_port.
extern size_t OFFSET(ipc_port, ip_bits);
extern size_t OFFSET(ipc_port, ip_references);
extern size_t OFFSET(ipc_port, ip_receiver);
extern size_t OFFSET(ipc_port, ip_kobject);
extern size_t OFFSET(ipc_port, ip_mscount);
extern size_t OFFSET(ipc_port, ip_srights);

// Parameters for struct ipc_space.
extern size_t OFFSET(ipc_space, is_table_size);
extern size_t OFFSET(ipc_space, is_table);
extern size_t OFFSET(ipc_space, is_task);

// Parameters for struct proc.
extern size_t OFFSET(proc, p_list_next);
extern size_t OFFSET(proc, task);
extern size_t OFFSET(proc, p_pid);
extern size_t OFFSET(proc, p_ucred);

// Parameters for struct task.
extern size_t OFFSET(task, lck_mtx_type);
extern size_t OFFSET(task, lck_mtx_data);
extern size_t OFFSET(task, ref_count);
extern size_t OFFSET(task, active);
extern size_t OFFSET(task, map);
extern size_t OFFSET(task, itk_sself);
extern size_t OFFSET(task, itk_space);
extern size_t OFFSET(task, bsd_info);
extern size_t OFFSET(task, all_image_info_addr);

// Parameters for IOSurface.
extern size_t OFFSET(IOSurface, properties);

// Parameters for IOSurfaceClient.
extern size_t OFFSET(IOSurfaceClient, surface);

// Parameters for IOSurfaceRootUserClient.
extern size_t OFFSET(IOSurfaceRootUserClient, surfaceClients);

// Parameters for OSArray.
extern size_t OFFSET(OSArray, count);
extern size_t OFFSET(OSArray, array);

// Parameters for OSData.
extern size_t OFFSET(OSData, capacity);
extern size_t OFFSET(OSData, data);

// Parameters for OSDictionary.
extern size_t OFFSET(OSDictionary, count);
extern size_t OFFSET(OSDictionary, dictionary);

// Parameters for OSString.
extern size_t OFFSET(OSString, string);

/*
 * parameters_init
 *
 * Description:
 * 	Initialize the parameters for the exploit.
 */
bool parameters_init(void);

#undef extern

#endif
