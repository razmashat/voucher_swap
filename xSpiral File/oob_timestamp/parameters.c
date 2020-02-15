/*
 * parameters.c
 * Brandon Azad
 */
#define PARAMETERS_EXTERN
#include "parameters.h"

#include "log.h"
#include "platform.h"
#include "platform_match.h"

// ---- Initialization routines -------------------------------------------------------------------

// A struct describing an initialization.
struct initialization {
	const char *devices;
	const char *builds;
	void (*init)(void);
};

// Run initializations matching this platform.
static size_t
run_initializations(struct initialization *inits, size_t count) {
	size_t match_count = 0;
	for (size_t i = 0; i < count; i++) {
		struct initialization *init = &inits[i];
		if (platform_matches(init->devices, init->builds)) {
			init->init();
			match_count++;
		}
	}
	return match_count;
}

// A helper macro to get the number of elements in a static array.
#define ARRAY_COUNT(x)	(sizeof(x) / sizeof((x)[0]))

// ---- Offset initialization ---------------------------------------------------------------------

// Initialization for iPhone12,3 17C54.
static void
offsets__iPad7_11__17C54() {
	OFFSET(host, special) = 0x10;

	SIZE(ipc_entry)              = 0x18;
	OFFSET(ipc_entry, ie_object) =  0x0;
	OFFSET(ipc_entry, ie_bits)   =  0x8;

	OFFSET(ipc_port, ip_bits)       =  0x0;
	OFFSET(ipc_port, ip_references) =  0x4;
	OFFSET(ipc_port, ip_receiver)   = 0x60;
	OFFSET(ipc_port, ip_kobject)    = 0x68; //here
	OFFSET(ipc_port, ip_mscount)    = 0x9c;
	OFFSET(ipc_port, ip_srights)    = 0xa0;

	OFFSET(ipc_space, is_table_size) = 0x14;
	OFFSET(ipc_space, is_table)      = 0x20;
	OFFSET(ipc_space, is_task)       = 0x28;

	OFFSET(proc, p_list_next) =  0x0;
	OFFSET(proc, task)        = 0x10;
	OFFSET(proc, p_pid)       = 0x68;

	OFFSET(task, lck_mtx_data)        =   0x0;
	OFFSET(task, lck_mtx_type)        =   0xb;
	OFFSET(task, ref_count)           =  0x10;
	OFFSET(task, active)              =  0x14;
	OFFSET(task, map)                 =  0x28;
	OFFSET(task, itk_sself)           = 0x108;
	OFFSET(task, itk_space)           = 0x320;
	OFFSET(task, bsd_info)            = 0x380;
	OFFSET(task, all_image_info_addr) = 0x3d0;

	OFFSET(IOSurface, properties) = 0xe8;

	OFFSET(IOSurfaceClient, surface) = 0x40;

	OFFSET(IOSurfaceRootUserClient, surfaceClients) = 0x118;

	OFFSET(OSArray, count) = 0x14;
	OFFSET(OSArray, array) = 0x20;

	OFFSET(OSData, capacity) = 0x10;
	OFFSET(OSData, data) = 0x18;

	OFFSET(OSDictionary, count) = 0x14;
	OFFSET(OSDictionary, dictionary) = 0x20;

	OFFSET(OSString, string) = 0x10;
    
    
    
}

// A list of offset initializations by platform.
static struct initialization offsets[] = {
	{ "iPad7,11", "17C54", offsets__iPad7_11__17C54 },
};

// The minimum number of offsets that must match in order to declare a platform initialized.
static const size_t min_offsets = 1;

// ---- Public API --------------------------------------------------------------------------------

bool
parameters_init() {
	// Initialize offsets.
	size_t count = run_initializations(offsets, ARRAY_COUNT(offsets));
	if (count < min_offsets) {
		ERROR("No offsets for %s %s", platform.machine, platform.osversion);
		return false;
	}
	return true;
}
