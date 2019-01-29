#
# voucher_swap/analysis.py
# Brandon Azad
#
# Load the desired kernelcache into IDA Pro 7.2. Do not split by kext.
#

from collections import defaultdict
import idaapi
import idautils
import ida_search
import ida_xref
import idc
import struct

# ---- Utility functions --------------------------------------------------------------------------

def is_mapped(ea, size=1):
    return (idaapi.getseg(ea)
            and idc.get_segm_start(ea) == idc.get_segm_start(ea + size - 1))

def is_mapped_data(ea, size=1):
    return (idc.is_loaded(ea)
            and idc.get_segm_start(ea) == idc.get_segm_start(ea + size - 1))

def is_code_ptr(ea):
    return is_mapped_data(ea, 4) and idc.is_code(idc.get_full_flags(idc.get_qword(ea)))

def get_segm_by_name(name):
    return idc.get_segm_by_sel(idc.selector_by_name(name))

def is_code_segment(ea):
    return idc.get_segm_attr(ea, idc.SEGATTR_TYPE) == idc.SEG_CODE

def get_func_start(ea):
    return idc.get_func_attr(ea, idc.FUNCATTR_START)

def CachedStrings():
    if not hasattr(CachedStrings, 'strings'):
        CachedStrings.strings = idautils.Strings()
    if CachedStrings.strings[0] is None:
        CachedStrings.strings.refresh()
    return CachedStrings.strings

def find_string(string):
    for s in CachedStrings():
        if str(s) == string:
            return s.ea
    return idc.BADADDR

def find_substring(string):
    for s in CachedStrings():
        if string in str(s):
            return s.ea
    return idc.BADADDR

def xrefs_to(ea, xref_type=None):
    xrefs = []
    for xref in idautils.XrefsTo(ea):
        if xref_type is None or xref.type == xref_type:
            xrefs.append(xref)
    return xrefs

def xrefs_from(ea, xref_type=None):
    xrefs = []
    for xref in idautils.XrefsFrom(ea):
        if xref_type is None or xref.type == xref_type:
            xrefs.append(xref)
    return xrefs

def functions_with_xref_to(ea, xref_type=None):
    functions = set()
    for xref in xrefs_to(ea, xref_type):
        func = get_func_start(xref.frm)
        if func != idc.BADADDR:
            functions.add(func)
    functions = list(functions)
    functions.sort()
    return functions

def xrefs_from_range(start_ea, end_ea, xref_type=None):
    xrefs = []
    for insn in Instructions(start_ea, end_ea):
        xrefs.extend(xrefs_from(insn.ea, xref_type))
    return xrefs

def xrefs_from_fchunk(ea, xref_type=None):
    start_ea = idc.get_fchunk_attr(ea, idc.FUNCATTR_START)
    end_ea   = idc.get_fchunk_attr(ea, idc.FUNCATTR_END)
    return xrefs_from_range(start_ea, end_ea, xref_type)

def xrefs_from_func(ea, xref_type=None):
    xrefs = []
    for start_ea, end_ea in idautils.Chunks(ea):
        xrefs.extend(xrefs_from_range(start_ea, end_ea, xref_type))
    return xrefs

def get_basic_block(ea):
    func = idaapi.get_func(ea)
    flow = idaapi.FlowChart(func)
    for bb in flow:
        if bb.startEA <= ea < bb.endEA:
            return bb.startEA, bb.endEA
    return get_func_start(ea), idc.find_func_end(ea)

def get_relative_func(ea, delta):
    hop = idc.get_next_func
    if delta < 0:
        delta = -delta
        hop = idc.get_prev_func
    for i in range(delta):
        ea = hop(ea)
    return ea

def _instructions_by_range(start, end):
    """A generator to iterate over instructions in a range."""
    pc = start
    while pc < end:
        insn = idautils.DecodeInstruction(pc)
        if insn is None:
            break
        next_pc = pc + insn.size
        if next_pc > end:
            raise AlignmentError(end)
        yield insn
        pc = next_pc

def _instructions_by_count(pc, count):
    """A generator to iterate over a specified number of instructions."""
    for i in xrange(count):
        insn = idautils.DecodeInstruction(pc)
        if insn is None:
            break
        yield insn
        pc += insn.size

def Instructions(start, end=None, count=None):
    """A generator to iterate over instructions.

    Instructions are decoded using IDA's DecodeInstruction(). If an address range is specified and
    the end of the address range does not fall on an instruction boundary, raises an
    AlignmentError.

    Arguments:
        start: The linear address from which to start decoding instructions.

    Options:
        end: The linear address at which to stop, exclusive.
        count: The number of instructions to decode.

    Notes:
        Exactly one of end and count must be specified.
    """
    if (end is not None and count is not None) or (end is None and count is None):
        raise ValueError('Invalid arguments: end={}, count={}'.format(end, count))
    if end is not None:
        return _instructions_by_range(start, end)
    else:
        return _instructions_by_count(start, count)

class OneToOneMapFactory(object):
    """A factory to extract the largest one-to-one submap."""

    def __init__(self):
        self._as_to_bs = defaultdict(set)
        self._bs_to_as = defaultdict(set)

    def add_link(self, a, b):
        """Add a link between the two objects."""
        self._as_to_bs[a].add(b)
        self._bs_to_as[b].add(a)

    def _make_unique_oneway(self, xs_to_ys, ys_to_xs, bad_x=None):
        """Internal helper to make one direction unique."""
        for x, ys in xs_to_ys.items():
            if len(ys) != 1:
                if bad_x:
                    bad_x(x, ys)
                del xs_to_ys[x]
                for y in ys:
                    del ys_to_xs[y]

    def _build_oneway(self, xs_to_ys):
        """Build a one-way mapping after pruning."""
        x_to_y = dict()
        for x, ys in xs_to_ys.items():
            x_to_y[x] = next(iter(ys))
        return x_to_y

    def build(self, bad_a=None, bad_b=None):
        """Extract the smallest one-to-one submap."""
        as_to_bs = dict(self._as_to_bs)
        bs_to_as = dict(self._bs_to_as)
        self._make_unique_oneway(as_to_bs, bs_to_as, bad_a)
        self._make_unique_oneway(bs_to_as, as_to_bs, bad_b)
        return self._build_oneway(as_to_bs)

# ---- Initialization -----------------------------------------------------------------------------

def analysis_init():
    convert_pointers_to_offsets()
    convert_code_data_to_code()

def convert_pointers_to_offsets():
    # Iterate through each segment.
    for seg_ea in idautils.Segments():
        # Skip __TEXT_EXEC segments, since they're big and less likely to contain pointers.
        if idc.get_segm_name(seg_ea).startswith('__TEXT_EXEC'):
            continue
        # Iterate through possible pointers in the segment. We'll use a granularity of 4 bytes for
        # speed.
        for ea in range(seg_ea, idc.get_segm_end(seg_ea), 4):
            # If this is a pointer, convert it to an offset.
            convert_pointer_to_offset(ea)

def convert_pointer_to_offset(ea):
        # If this is code, skip it.
        flags = idc.get_full_flags(ea)
        if idc.is_code(flags):
            return
        # If the value at this address does not point into the kernelcache, skip it.
        value = idc.get_qword(ea)
        if not is_mapped(value, 8):
            return
        # Convert this value to a qword (in case it's unaligned) and then convert it into an
        # offset.
        idc.create_qword(ea)
        idc.op_plain_offset(ea, 0, 0)

def convert_code_data_to_code():
    regions = []
    # Iterate through each segment, gathering all the code data regions.
    for seg_ea in idautils.Segments():
        # Only process __TEXT_EXEC segments.
        seg_name = idc.get_segm_name(seg_ea)
        if not (seg_name.startswith('__TEXT_EXEC')
                or seg_name.startswith('__PLK_TEXT_EXEC')):
            continue
        # Convert all code data regions to code.
        regions.extend(gather_code_data_regions(seg_ea, idc.get_segm_end(seg_ea)))
    # Iterate through the regions, converting them to code.
    for region_start, region_end in regions:
        convert_code_data_region_to_code(region_start, region_end)

def gather_code_data_regions(start_ea, end_ea):
    regions = []
    unnamed_data_mask = idc.FF_REF | idc.FF_ANYNAME | idc.DT_TYPE | idc.FF_CODE | idc.FF_DATA
    unkn_flags  = idc.FF_UNK                    # Unnamed, unknown data
    dword_flags = idc.FF_DATA | idc.FF_DWORD    # An unnamed dword
    qword_flags = idc.FF_DATA | idc.FF_QWORD    # An unnamed qword
    unnamed_data_flags = (qword_flags, dword_flags, unkn_flags)
    named_data_mask = idc.FF_REF | idc.FF_ANYNAME | idc.FF_CODE | idc.FF_DATA
    named_data_flags = idc.FF_REF | idc.FF_LABL | idc.FF_DATA
    # Iterate 4 bytes (1 instruction) at a time.
    ea = start_ea
    while ea < end_ea:
        flags = idc.get_full_flags(ea)
        # Check if we have an unnamed dword or qword following code.
        if (flags & unnamed_data_mask) in unnamed_data_flags:
            # This is a bad region. Coalesce any subsequent bad regions.
            region_start = ea
            while True:
                ea = idc.get_item_end(ea)
                if ea >= end_ea:
                    break
                flags = idc.get_full_flags(ea)
                if (flags & unnamed_data_mask) not in unnamed_data_flags:
                    # Check if this is a dummy reference and this is actually code.
                    if (flags & named_data_mask) == named_data_flags:
                        end = idc.get_item_end(ea)
                        size = end - ea
                        if size in (1,2,4,8):
                            score, _ = code_score(ea, end)
                            if score == 1.0:
                                #print 'FORCE  {:016x}  {:x}'.format(ea, size)
                                continue
                    break
            # This is the end of the coalesced bad region.
            region_end = ea
            regions.append((region_start, region_end))
            # Advance past this region.
            last_flags = 0
        else:
            # This is not a bad region. Advance 1 instruction.
            ea += 4
    return regions

def convert_code_data_region_to_code(start_ea, end_ea):
    size = end_ea - start_ea
    score, count = code_score(start_ea, end_ea)
    if score >= 0.75:
        #print '{:016x}  {:8x}  {}'.format(start_ea, size, score)
        idc.del_items(start_ea, idc.DELIT_SIMPLE, size)
        for ea in range(start_ea, end_ea, 4):
            ilen = idc.create_insn(ea)
            if ilen == 0:
                idc.create_dword(ea)

def code_score(start_ea, end_ea):
    code_count = 0
    total_count = 0
    for ea in range(start_ea, end_ea, 4):
        if idautils.DecodeInstruction(ea):
            code_count += 1
        total_count += 1
    return float(code_count) / total_count, total_count

# ---- Emulator -----------------------------------------------------------------------------------

class UnknownType:
    """A numeric class indicating that the value is unknown."""
    def __repr__(self):
        return 'Unknown'
    def __add__(self, other):
        return Unknown
    def __and__(self, other):
        return Unknown
    def __div__(self, other):
        return Unknown
    def __lshift__(self, other):
        return Unknown
    def __mod__(self, other):
        return Unknown
    def __mul__(self, other):
        return Unknown
    def __neg__(self, other):
        return Unknown
    def __or__(self, other):
        return Unknown
    def __nonzero__(self):
        return False
    def __rshift__(self, other):
        return Unknown
    def __sub__(self, other):
        return Unknown
    def __xor__(self, other):
        return Unknown
    def __radd__(self, other):
        return Unknown
    def __rand__(self, other):
        return Unknown
    def __rdiv__(self, other):
        return Unknown
    def __rlshift__(self, other):
        return Unknown
    def __rmod__(self, other):
        return Unknown
    def __rmul__(self, other):
        return Unknown
    def __ror__(self, other):
        return Unknown
    def __rrshift__(self, other):
        return Unknown
    def __rsub__(self, other):
        return Unknown
    def __rxor__(self, other):
        return Unknown

Unknown = UnknownType()

class Arm64Emulator(object):
    # IDK where IDA defines these.
    _MEMOP_PREINDEX  = 0x20
    _MEMOP_POSTINDEX = 0x80
    _MEMOP_WBINDEX   = _MEMOP_PREINDEX | _MEMOP_POSTINDEX

    class _Regs(object):
        Names = idautils.GetRegisterList()

        def __init__(self):
            self.clearall()

        def _reg(self, reg):
            if isinstance(reg, (int, long)):
                reg = Arm64Emulator._Regs.Names[reg]
            elif isinstance(reg, str):
                reg = reg.upper()
            return reg

        def clearall(self):
            self._regs = {}

        def clear(self, reg):
            try:
                del self._regs[self._reg(reg)]
            except KeyError:
                pass

        def __getitem__(self, reg):
            try:
                return self._regs[self._reg(reg)]
            except:
                return Unknown

        def __setitem__(self, reg, value):
            if value is None or value is Unknown:
                self.clear(reg)
            else:
                self._regs[self._reg(reg)] = value & 0xffffffffffffffff

    def __init__(self):
        self.clear()

    def clear(self):
        self.regs = Arm64Emulator._Regs()

    def load(self, addr, dtyp):
        if addr is Unknown:
            return Unknown
        if not is_mapped_data(addr):
            return Unknown
        if dtyp == idaapi.dt_qword:
            return idc.get_qword(addr)
        elif dtyp == idaapi.dt_dword:
            return idc.get_wide_dword(addr)
        elif dtyp == idaapi.dt_word:
            return idc.get_wide_word(addr)
        elif dtyp == idaapi.dt_byte:
            return idc.get_wide_byte(addr)
        return Unknown

    def clear_temporary_registers(self):
        for t in ['X{}'.format(i) for i in range(0, 19)]:
            self.regs.clear(t)

    def BL(self, bl_addr):
        pass

    def RET(self):
        pass

    def run(self, start, end):
        for insn in Instructions(start, end):
            mnem = insn.get_canon_mnem()
            if mnem == 'ADRP' or mnem == 'ADR':
                self.regs[insn.Op1.reg] = insn.Op2.value
            elif mnem == 'ADD' and insn.Op2.type == idc.o_reg and insn.Op3.type == idc.o_imm:
                self.regs[insn.Op1.reg] = self.regs[insn.Op2.reg] + insn.Op3.value
            elif mnem == 'NOP':
                pass
            elif mnem == 'MOV' and insn.Op2.type == idc.o_imm:
                self.regs[insn.Op1.reg] = insn.Op2.value
            elif mnem == 'MOV' and insn.Op2.type == idc.o_reg:
                self.regs[insn.Op1.reg] = self.regs[insn.Op2.reg]
            elif mnem == 'RET':
                self.RET()
                break
            elif (mnem == 'STP' or mnem == 'LDP') and insn.Op3.type == idc.o_displ:
                if insn.auxpref & Arm64Emulator._MEMOP_WBINDEX:
                    self.regs[insn.Op3.reg] = self.regs[insn.Op3.reg] + insn.Op3.addr
                if mnem == 'LDP':
                    self.regs.clear(insn.Op1.reg)
                    self.regs.clear(insn.Op2.reg)
            elif ((mnem == 'STR' or mnem == 'LDR')
                    and not insn.auxpref & Arm64Emulator._MEMOP_WBINDEX):
                if mnem == 'LDR':
                    if insn.Op2.type == idc.o_displ:
                        load_addr = self.regs[insn.Op2.reg] + insn.Op2.addr
                        self.regs[insn.Op1.reg] = self.load(load_addr, insn.Op1.dtyp)
                    else:
                        self.regs.clear(insn.Op1.reg)
            elif mnem == 'BL' and insn.Op1.type == idc.o_near:
                self.BL(insn.Op1.addr)
                self.clear_temporary_registers()
            else:
                self.regs.clearall()

# ---- Metaclass ----------------------------------------------------------------------------------

metaclass_to_classname = {}
classname_to_metaclass = {}

def process_metaclasses():
    global metaclass_to_classname, classname_to_metaclass
    metaclass_to_classname = map_metaclasses_to_classnames()
    for metaclass, classname in metaclass_to_classname.items():
        classname_to_metaclass[classname] = metaclass

def map_metaclasses_to_classnames():
    map_builder = OneToOneMapFactory()
    def found_metaclass(metaclass, classname):
        map_builder.add_link(metaclass, classname)
    process_mod_init_funcs_for_metaclasses(found_metaclass)
    def bad_metaclass(metaclass, classnames):
        print 'Metaclass {:#x} has multiple classes: {}'.format(metaclass,
                ', '.join(classnames))
    def bad_classname(classname, metaclasses):
        print 'Class {} has multiple metaclasses: {}'.format(classname,
                ', '.join('{:#x}'.format(mc) for mc in metaclasses))
    return map_builder.build(bad_metaclass, bad_classname)

def process_mod_init_funcs_for_metaclasses(found_metaclass):
    # Iterate through all segments.
    for seg_ea in idautils.Segments():
        # Only process __mod_init_func and __kmod_init segments.
        seg_name = idc.get_segm_name(seg_ea)
        if not (seg_name.endswith('__mod_init_func')
                or seg_name.endswith('__kmod_init')):
            continue
        # Process the segment.
        seg_end = idc.get_segm_end(seg_ea)
        process_mod_init_segment_for_metaclasses(seg_ea, seg_end, found_metaclass)

def process_mod_init_segment_for_metaclasses(start, end, found_metaclass):
    for ea in range(start, end, 8):
        func = idc.get_qword(ea)
        process_mod_init_func_for_metaclasses(func, found_metaclass)

def process_mod_init_func_for_metaclasses(func, found_metaclass):
    class FindMetaclassEmulator(Arm64Emulator):
        def BL(self, bl_addr):
            # OSMetaClass::OSMetaClass(this, className, superclass, classSize)
            X0, X1, X3 = (self.regs[n] for n in ('X0', 'X1', 'X3'))
            if (X0 and X1 and X3
                    and idc.get_segm_name(X1).endswith("__cstring")
                    and idc.get_segm_name(X0)):
                found_metaclass(X0, idc.get_strlit_contents(X1))
    FindMetaclassEmulator().run(func, idc.find_func_end(func))

# ---- Vtable -------------------------------------------------------------------------------------

metaclass_to_vtable = {}
vtable_length = {}

def process_vtables():
    global metaclass_to_vtable, vtable_length
    metaclass_to_vtable, vtable_length = map_metaclasses_to_vtables(metaclass_to_classname)

def vtable_for_class(classname):
    try:
        metaclass = classname_to_metaclass[classname]
        return metaclass_to_vtable[metaclass]
    except:
        return None

def map_metaclasses_to_vtables(metaclass_to_classname_map):
    vtable_lengths = {}
    map_builder = OneToOneMapFactory()
    def found_vtable(vtable, length, metaclass):
        vtable_lengths[vtable] = length
        map_builder.add_link(metaclass, vtable)
    metaclasses = metaclass_to_classname_map.keys()
    process_all_vtables(metaclasses, found_vtable)
    def bad_metaclass(metaclass, vtables):
        classname = metaclass_to_classname_map[metaclass]
        if classname != 'OSMetaClass':
            print 'Metaclass {} {:#x} has multiple vtables: {}'.format(
                    classname, metaclass,
                    ', '.join('{:#x}'.format(vt) for vt in vtables))
    metaclass_to_vtable_map = map_builder.build(bad_metaclass, None)
    return metaclass_to_vtable_map, vtable_lengths

def process_all_vtables(metaclasses, found_vtable):
    # Iterate through all segments.
    for seg_ea in idautils.Segments():
        # Only process __const segments.
        if not idc.get_segm_name(seg_ea).endswith('__const'):
            continue
        # Process the segment.
        seg_end = idc.get_segm_end(seg_ea)
        process_segment_for_vtables(seg_ea, seg_end, metaclasses, found_vtable)

def process_segment_for_vtables(start, end, metaclasses, found_vtable):
    # Iterate over each address in the segment.
    ea = start
    while ea < end:
        # Check whether this is a possible vtable. If so, get the corresponding metaclass.
        possible_vtable, length = check_vtable(ea)
        if possible_vtable:
            metaclass = get_metaclass_for_vtable(ea, length)
            if metaclass in metaclasses:
                found_vtable(ea, length, metaclass)
        # Skip past the vtable. Also skip past the next word: if we found a vtable then it's zero,
        # otherwise it's not a code pointer.
        ea += (length + 1) * 8

def get_metaclass_for_vtable(vtable, length):
    # Get the address of the ::getMetaClass() method.
    OSObject_method_count = 12
    getMetaClass_index    = 7
    if length <= OSObject_method_count:
        return None
    getMetaClass = idc.get_qword(vtable + 8 * getMetaClass_index)
    # Emulate the method to get the return value.
    class GetReturnEmulator(Arm64Emulator):
        def __init__(self):
            super(GetReturnEmulator, self).__init__()
            self.return_value = None
        def RET(self):
            self.return_value = self.regs['X0']
    emulator = GetReturnEmulator()
    getMetaClass_end = getMetaClass + 4 * 4
    emulator.run(getMetaClass, getMetaClass_end)
    return emulator.return_value

def check_vtable(start, end=None):
    # We recognize a vtable by looking for an array of at least 2 pointers to code followed by a
    # NULL.
    # If no end was specified, go until the end of the segment.
    if end is None:
        end = idc.get_segm_end(start)
    # Check each address in the table. Stop once we've found something other than a pointer to
    # code.
    ended_with_zero = False
    ea = start
    while ea < end:
        method = idc.get_qword(ea)
        if method == 0:
            ended_with_zero = True
            break
        if not idc.is_code(idc.get_full_flags(method)):
            break
        ea += 8
    # Compute the length.
    length = (ea - start) / 8
    possible_vtable = ended_with_zero and length >= 2
    return possible_vtable, length

# ---- PAC ----------------------------------------------------------------------------------------

def extract_vtable_pac_codes(vtable_ea):
    pac_codes = []
    # Open the file.
    path = idc.get_input_file_path()
    with open(path, "rb") as kernelcache_file:
        # Seek to the offset of the vtable.
        offset = idaapi.get_fileregion_offset(vtable_ea)
        kernelcache_file.seek(offset)
        # Loop over each entry in the vtable.
        ea = vtable_ea
        while True:
            # Break if we've reached the end of the vtable.
            vmethod = idc.get_qword(ea)
            if vmethod == 0:
                break
            # Get the original value from the original file.
            original = kernelcache_file.read(8)
            value, = struct.unpack("<Q", original)
            # Extract the type code and add it to the list.
            pac_code = (value & 0x0000ffff00000000) >> 32
            pac_codes.append(pac_code)
            # Advance.
            ea += 8
    return pac_codes

