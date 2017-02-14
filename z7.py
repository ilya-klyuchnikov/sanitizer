import struct
import array

# http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
MACHINE_OFFSET = 0
MACHINE_FORMAT = '<H'

NUMBER_OF_SECTIONS_OFFSET = 2
NUMBER_OF_SECTIONS_FORMAT = '<H'

TIME_DATE_STAMP_OFFSET = 4
TIME_DATE_STAMP_FORMAT = '<I'

POINTER_TO_SYMBOL_TABLE_OFFSET = 8
POINTER_TO_SYMBOL_TABLE_FORMAT = '<I'

NUMBER_OF_SYMBOLS_OFFSET = 12
NUMBER_OF_SYMBOLS_FORMAT = '<I'

SIZE_OF_OPTIONAL_HEADER_OFFSET = 16
SIZE_OF_OPTIONAL_HEADER_FORMAT = '<H'

CHARACTERISTICS_OFFSET = 18
CHARACTERISTICS_FORMAT = '<H'

COFF_FILE_HEADER_SIZE = 20

# 4. Section Table (Section Headers)
SECTION_HEADERS_START = 20
SECTION_HEADER_SIZE = 40

SECTION_HEADER_NAME_OFFSET = 0
SECTION_HEADER_NAME_FORMAT = '8s'
SECTION_HEADER_VIRTUAL_SIZE_OFFSET = 8
SECTION_HEADER_VIRTUAL_SIZE_FORMAT = '<I'
SECTION_HEADER_VIRTUAL_ADDRESS_OFFSET = 12
SECTION_HEADER_VIRTUAL_ADDRESS_FORMAT = '<I'
SECTION_HEADER_SIZE_OF_RAW_DATA_OFFSET = 16
SECTION_HEADER_SIZE_OF_RAW_DATA_FORMAT = '<I'
SECTION_HEADER_PTR_TO_RAW_DATA_OFFSET = 20
SECTION_HEADER_PTR_TO_RAW_DATA_FORMAT = '<I'
SECTION_HEADER_PTR_TO_RELOCATIONS_OFFSET = 24
SECTION_HEADER_PTR_TO_RELOCATIONS_FORMAT = '<I'
SECTION_HEADER_PTR_TO_LINE_NUMBERS_OFFSET = 28
SECTION_HEADER_PTR_TO_LINE_NUMBERS_FORMAT = '<I'
SECTION_HEADER_NUMBER_OF_RELOCATIONS_OFFSET = 32
SECTION_HEADER_NUMBER_OF_RELOCATIONS_FORMAT = '<H'
SECTION_HEADER_NUMBER_OF_LINENUMBERS_OFFSET = 34
SECTION_HEADER_NUMBER_OF_LINENUMBERS_FORMAT = '<H'
SECTION_HEADER_CHARACTERISTICS_OFFSET = 36
SECTION_HEADER_CHARACTERISTICS_FORMAT = '<I'

RELOCATION_SIZE = 10
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_LNK_COMDAT = 0x00001000

SYMBOL_SIZE = 18
AUX_SYMBOLS_FORMAT = '<B'
AUX_SYMBOLS_OFFSET = 17
SECTION_SYMBOL_FORMAT = '<h'
SECTION_SYMBOL_OFFSET = 12


class FileHeader(object):
    def __init__(self, data):
        self.machine, = struct.unpack_from(
            MACHINE_FORMAT,
            data,
            MACHINE_OFFSET
        )

        self.number_of_sections, = struct.unpack_from(
            NUMBER_OF_SECTIONS_FORMAT,
            data,
            NUMBER_OF_SECTIONS_OFFSET
        )

        self.time_date_stamp, = struct.unpack_from(
            TIME_DATE_STAMP_FORMAT,
            data,
            TIME_DATE_STAMP_OFFSET
        )

        self.pointer_to_symbol_table, = struct.unpack_from(
            POINTER_TO_SYMBOL_TABLE_FORMAT,
            data,
            POINTER_TO_SYMBOL_TABLE_OFFSET
        )

        self.number_of_symbols, = struct.unpack_from(
            NUMBER_OF_SYMBOLS_FORMAT,
            data,
            NUMBER_OF_SYMBOLS_OFFSET
        )

        self.size_of_optional_header, = struct.unpack_from(
            SIZE_OF_OPTIONAL_HEADER_FORMAT,
            data,
            SIZE_OF_OPTIONAL_HEADER_OFFSET
        )

        self.characteristics, = struct.unpack_from(
            CHARACTERISTICS_FORMAT,
            data,
            CHARACTERISTICS_OFFSET
        )

        # /GL compilation is not supported
        assert self.size_of_optional_header == 0

    def write(self, output):
        output.fromstring(
            struct.pack(MACHINE_FORMAT, self.machine))
        output.fromstring(
            struct.pack(NUMBER_OF_SECTIONS_FORMAT, self.number_of_sections))
        output.fromstring(
            struct.pack(TIME_DATE_STAMP_FORMAT, self.time_date_stamp)) # SIC
        output.fromstring(
            struct.pack(POINTER_TO_SYMBOL_TABLE_FORMAT, self.pointer_to_symbol_table))
        output.fromstring(
            struct.pack(NUMBER_OF_SYMBOLS_FORMAT, self.number_of_symbols))
        output.fromstring(
            struct.pack(SIZE_OF_OPTIONAL_HEADER_FORMAT, self.size_of_optional_header))
        output.fromstring(
            struct.pack(CHARACTERISTICS_FORMAT, self.characteristics))


class SectionHeader(object):
    def __init__(self, data, section_start):
        self.name, = struct.unpack_from(
            SECTION_HEADER_NAME_FORMAT,
            data,
            section_start + SECTION_HEADER_NAME_OFFSET,
        )
        self.virtual_size, = struct.unpack_from(
            SECTION_HEADER_VIRTUAL_SIZE_FORMAT,
            data,
            section_start + SECTION_HEADER_VIRTUAL_SIZE_OFFSET,
        )
        self.virtual_address, = struct.unpack_from(
            SECTION_HEADER_VIRTUAL_ADDRESS_FORMAT,
            data,
            section_start + SECTION_HEADER_VIRTUAL_ADDRESS_OFFSET,
        )
        self.size_of_raw_data, = struct.unpack_from(
            SECTION_HEADER_SIZE_OF_RAW_DATA_FORMAT,
            data,
            section_start + SECTION_HEADER_SIZE_OF_RAW_DATA_OFFSET,
        )
        self.ptr_to_raw_data, = struct.unpack_from(
            SECTION_HEADER_PTR_TO_RAW_DATA_FORMAT,
            data,
            section_start + SECTION_HEADER_PTR_TO_RAW_DATA_OFFSET,
        )
        self.ptr_to_relocations, = struct.unpack_from(
            SECTION_HEADER_PTR_TO_RELOCATIONS_FORMAT,
            data,
            section_start + SECTION_HEADER_PTR_TO_RELOCATIONS_OFFSET,
        )
        self.ptr_to_linenumbers, = struct.unpack_from(
            SECTION_HEADER_PTR_TO_LINE_NUMBERS_FORMAT,
            data,
            section_start + SECTION_HEADER_PTR_TO_LINE_NUMBERS_OFFSET,
        )
        self.number_of_relocations, = struct.unpack_from(
            SECTION_HEADER_NUMBER_OF_RELOCATIONS_FORMAT,
            data,
            section_start + SECTION_HEADER_NUMBER_OF_RELOCATIONS_OFFSET,
        )
        self.numbers_of_linenumbers, = struct.unpack_from(
            SECTION_HEADER_NUMBER_OF_LINENUMBERS_FORMAT,
            data,
            section_start + SECTION_HEADER_NUMBER_OF_LINENUMBERS_OFFSET,
        )
        self.characteristics, = struct.unpack_from(
            SECTION_HEADER_CHARACTERISTICS_FORMAT,
            data,
            section_start + SECTION_HEADER_CHARACTERISTICS_OFFSET
        )

    def write(self, output):
        output.fromstring(
            struct.pack(SECTION_HEADER_NAME_FORMAT, self.name))
        output.fromstring(
            struct.pack(SECTION_HEADER_VIRTUAL_SIZE_FORMAT, self.virtual_size))
        output.fromstring(
            struct.pack(SECTION_HEADER_VIRTUAL_ADDRESS_FORMAT, self.virtual_address))
        output.fromstring(
            struct.pack(SECTION_HEADER_SIZE_OF_RAW_DATA_FORMAT, self.size_of_raw_data))
        output.fromstring(
            struct.pack(SECTION_HEADER_PTR_TO_RAW_DATA_FORMAT, self.ptr_to_raw_data))
        output.fromstring(
            struct.pack(SECTION_HEADER_PTR_TO_RELOCATIONS_FORMAT, self.ptr_to_relocations))
        output.fromstring(
            struct.pack(SECTION_HEADER_PTR_TO_LINE_NUMBERS_FORMAT, self.ptr_to_linenumbers))
        output.fromstring(
            struct.pack(SECTION_HEADER_NUMBER_OF_RELOCATIONS_FORMAT, self.number_of_relocations))
        output.fromstring(
            struct.pack(SECTION_HEADER_NUMBER_OF_LINENUMBERS_FORMAT, self.numbers_of_linenumbers))
        output.fromstring(
            struct.pack(SECTION_HEADER_CHARACTERISTICS_FORMAT, self.characteristics))

    def should_strip_section(self):
        # IMAGE_SCN_LNK_COMDAT - debug$S may have IMAGE_SCN_LNK_COMDAT for imported functions
        return False


def read_section_headers(data, number_of_sections):
    """read section headers from binaries"""
    sections = []
    for section_i in range(0, number_of_sections):
        section = SectionHeader(
            data,
            SECTION_HEADERS_START + (section_i * SECTION_HEADER_SIZE)
        )
        sections.append(section)
    return sections

#define CV_SIGNATURE_C7         1L  // First explicit signature
#define CV_SIGNATURE_C11        2L  // C11 (vc5.x) 32-bit types
#define CV_SIGNATURE_C13        4L  // C13 (vc7.x) zero terminated names

DEBUG_S_SYMBOLS = 0xf1
DEBUG_S_STRINGTABLE = 243
DEBUG_S_FILECHKSMS  = 244
DEBUG_S_FRAMEDATA   = 245
S_OBJNAME       =  0x1101  # path to object file name
S_BUILDINFO      = 0x114c

LF_BUILDINFO     = 0x1603
LF_SUBSTR_LIST   = 0x1604
LF_STRING_ID     = 0x1605

class DebugSection(object):
    def __init__(self, subsections):
        self.subsections = subsections

    def dump(self):
        for subsection in self.subsections:
            subsection.dump()

    def patch(self):
        for subsection in self.subsections:
            subsection.patch()

    def patched_result(self, data_output):
        data_output.fromstring(struct.pack('<I', 4))
        for subsection in self.subsections:
            sub_output = array.array('b')
            subsection.patched_result(sub_output)
            data_output.extend(sub_output)
            ln = len(sub_output)
            if (ln % 4) != 0:
                 padding = 4 - (ln % 4)
                 data_output.extend(bytearray(padding))


class DebugSubsection(object):
    pass


class DebugGenericSubsection(DebugSubsection):
    def __init__(self, subsection_type, subsection_len, subsection_data):
        self.subsection_type = subsection_type
        self.subsection_len = subsection_len
        self.subsection_data = subsection_data

    def dump(self):
        pass

    def patch(self):
        pass

    def patched_result(self, data_output):
        data_output.fromstring(struct.pack('<I', self.subsection_type))
        data_output.fromstring(struct.pack('<I', self.subsection_len))
        data_output.fromstring(self.subsection_data)

RELOCATION_SHIFT = [False, 0, True]

class DebugSymbolsSubsection(DebugSubsection):
    def __init__(self, subsection_type, subsection_len, symbols):
        self.subsection_type = subsection_type
        self.subsection_len = subsection_len
        self.symbols = symbols

    def dump(self):
        for symbol in self.symbols:
            symbol.dump()

    def patch(self):
        for symbol in self.symbols:
            symbol.patch()

    def patched_result(self, data_output):
        # data_output.fromstring(struct.pack('<I', DEBUG_S_SYMBOLS))
        # data_output.fromstring(struct.pack('<I', 100))
        data_output.fromstring(struct.pack('<I', self.subsection_type))

        sub_output = array.array('b')
        for symbol in self.symbols:
            symbol.patched_result(sub_output)

        old_subsec_len = self.subsection_len
        new_subsec_len = len(sub_output)
        data_output.fromstring(struct.pack('<I', new_subsec_len))

        if (new_subsec_len % 4) != 0:
            padding1 = 4 - (new_subsec_len % 4)
            new_subsec_len += padding1

        if (old_subsec_len % 4) != 0:
            padding2 = 4 - (old_subsec_len % 4)
            old_subsec_len += padding2

        print "SYMBOLS>> OLD: {0}, NEW: {1}".format(hex(old_subsec_len), hex(new_subsec_len))
        if not RELOCATION_SHIFT[0]:
            RELOCATION_SHIFT[0] = True
            RELOCATION_SHIFT[1] = new_subsec_len - old_subsec_len

        data_output.extend(sub_output)


class DebugFramedataSubsection(DebugSubsection):
    def __init__(self, subsection_type, subsection_len, subsection_data):
        self.subsection_type = subsection_type
        self.subsection_len = subsection_len
        self.subsection_data = subsection_data

    def dump(self):
        print '  FRAMEDATA'
        # the size of data - 32
        ppointer, = struct.unpack_from('<I', self.subsection_data,  24)
        print '    pointer: {0}'.format(hex(ppointer))

    def patch(self):
        pass

    def patched_result(self, data_output):
        # data_output.fromstring(struct.pack('<I', DEBUG_S_FRAMEDATA))
        # data_output.fromstring(struct.pack('<I', 100))
        data_output.fromstring(struct.pack('<I', self.subsection_type))
        data_output.fromstring(struct.pack('<I', self.subsection_len))
        assert self.subsection_len == 32 + 4
        data_output.fromstring(self.subsection_data[:24])
        ppointer, = struct.unpack_from('<I', self.subsection_data, 24)
        if ppointer in mapping:
            ppointer = mapping[ppointer]
        data_output.fromstring(struct.pack('<I', ppointer))
        data_output.fromstring(self.subsection_data[28:])



class DebugStringTableSubsection(DebugSubsection):
    def __init__(self, subsection_type, subsection_len, subsection_data):
        self.subsection_type = subsection_type
        self.subsection_len = subsection_len
        self.subsection_data = subsection_data
        self.init()

    def dump(self):
        print '  STRINGTABLE'
        table = self.subsection_data
        strs = table.split('\0')
        print strs

    def patch(self):
        pass

    def init(self):
        table = self.subsection_data
        delims = []
        strings = []
        delim = table.find('\0')
        delims.append(delim)
        print hex(delim)
        s = table[0:delim + 1]
        print s
        strings.append(s)
        while True:
            next_delim = table.find('\0', delim + 1)
            if next_delim == -1:
                break
            delims.append(delim + 1)
            print hex(delim + 1)
            s = table[delim + 1: next_delim + 1]
            strings.append(s)
            print s
            delim = next_delim

        ss1 = []
        s11 = s1.lower()
        s21 = s2.lower()
        ss1 = [x.replace(s11, s21) for x in strings]

        next_indices = [0]
        inx = 0
        for i in range(0, len(ss1) - 1):
            inx += len(ss1[i])
            next_indices.append(inx)

        for n in next_indices:
            print(hex(n))

        for i in range(0, len(ss1)):
            mapping[delims[i]] = next_indices[i]
            print '{0} -> {1}'.format(hex(delims[i]), hex(next_indices[i]))

        #print subst

    def patched_result(self, data_output):
        result = self.subsection_data
        if result.find(s1) != -1:
            result = result.replace(s1, s2)

        if result.find(s11) != -1:
            result = result.replace(s11, s21)
        sub_output = array.array('b')
        sub_output.fromstring(result)

        data_output.fromstring(struct.pack('<I', self.subsection_type))
        data_output.fromstring(struct.pack('<I', len(sub_output)))
        data_output.extend(sub_output)


class DebugFileChkSumSubsection(DebugSubsection):
    def __init__(self, subsection_type, subsection_len, subsection_data):
        self.subsection_type = subsection_type
        self.subsection_len = subsection_len
        self.subsection_data = subsection_data

    def dump(self):
        ibSym = 0
        left = len(self.subsection_data)
        print '  FILECHKSMS'
        while left > 0:
            my_data = self.subsection_data[ibSym:ibSym + 24]
            offset, = struct.unpack_from('<I', my_data, 0)
            print '     oFFSET: {0}'.format(hex(offset))
            ibSym += 24
            left -= 24

    def patch(self):
        pass

    def patched_result(self, data_output):
        # data_output.fromstring(struct.pack('<I', DEBUG_S_FILECHKSMS))
        # data_output.fromstring(struct.pack('<I', 100))
        data_output.fromstring(struct.pack('<I', self.subsection_type))
        data_output.fromstring(struct.pack('<I', self.subsection_len))

        ibSym = 0
        left = len(self.subsection_data)
        #print '  FILECHKSMS'
        while left > 0:
            my_data = self.subsection_data[ibSym:ibSym + 24]
            offset, = struct.unpack_from('<I', my_data, 0)
            if offset in mapping:
                offset = mapping[offset]
                print 'OFFSET: {0}'.format(hex(offset))
            data_output.fromstring(struct.pack('<I', offset))
            data_output.fromstring(my_data[4:])
            ibSym += 24
            left -= 24


class Symbol(object):
    pass


class ObjNameSymbol(Symbol):
    def __init__(self, subsection_data):
        self.subsection_data = subsection_data

    def dump(self):
        reclen, = struct.unpack_from('<H', self.subsection_data, 0)  # 2
        type, = struct.unpack_from('<H', self.subsection_data, 2)  # 2
        type_len = 2
        signature = struct.unpack_from('<I', self.subsection_data, 4)
        signature_len = 4
        slen = reclen - signature_len - type_len  # (type, signature)
        slen_len = 2
        fmt = '{0}s'.format(slen)
        name, = struct.unpack_from(fmt, self.subsection_data, 8)
        # null terminated
        print '    S_OBJNAME: {0}'.format(name)


    def patch(self):
        name = self.subsection_data[8:]
        result = name.replace(s1, s2)
        print "   S_OBJNAME: {0} -> {1}".format(name, result)
        pass

    def patched_result(self, data_output):
        result = self.subsection_data
        if result.find(s1) != -1:
            result = result.replace(s1, s2)

        if result.find(s11) != -1:
            result = result.replace(s11, s21)
        data_output.fromstring(struct.pack('<H', len(result) - 2))
        data_output.fromstring(result[2:])


class BuildInfoSymbol(Symbol):
    def __init__(self, subsection_data):
        self.subsection_data = subsection_data

    def dump(self):
        reclen, = struct.unpack_from('<H', self.subsection_data, 0)  # 2
        id, = struct.unpack_from('<I', self.subsection_data, 4)
        print '    S_BUILDINFO: {0}'.format(hex(id))

    def patch(self):
        pass

    def patched_result(self, data_output):
        data_output.fromstring(self.subsection_data)


class GenericSymbol(Symbol):
    def __init__(self, subsection_data):
        self.subsection_data = subsection_data

    def dump(self):
        pass

    def patch(self):
        pass

    def patched_result(self, data_output):
        data_output.fromstring(self.subsection_data)


TYPES_SHIFT = i = 0x1000
class TypesSection(object):
    def __init__(self, leaves):
        self.leaves = leaves
        self.min_offset = len(leaves)

    def dump(self):
        i = 0x1000
        for leaf in self.leaves:
            leaf.dump(i)
            i += 1

    def patch(self):
        pass

    def patched_result(self, data_output):
        data_output.fromstring(struct.pack('<I', 4))
        for leaf in self.leaves[:self.build_info.offset]:
            leaf.patched_result(data_output)
        self.build_info.patch()
        self.build_info.serialize()
        for leaf in self.build_info.symbols:
            leaf.patched_result(data_output)


    def mkBuildInfo(self):
        build_info_leaf = self.leaves[-1]
        leaf_id = build_info_leaf.get_leaf_id()
        assert leaf_id == LF_BUILDINFO
        refs = build_info_leaf.get_ids()
        workdir = self.get_string(refs[0])
        build_tool = self.get_string(refs[1])
        source_file = self.get_string(refs[2])
        pdb = self.get_string(refs[3])
        args = self.get_string(refs[4])
        self.build_info = BuildInfo(self.min_offset, workdir, build_tool, source_file, pdb, args)


    def get_string(self, ref):
        leaf_index = ref - TYPES_SHIFT
        leaf = self.leaves[leaf_index]
        leaf_id = leaf.get_leaf_id()
        self.min_offset = min(self.min_offset, leaf_index)
        if leaf_id == LF_STRING_ID:
            ref = leaf.get_ref()
            result_s = ''
            if (ref > 0):
                result_s = self.get_string(ref)
            result_s += leaf.get_string()
            return result_s
        elif leaf_id == LF_SUBSTR_LIST:
            refs = leaf.get_refs()
            result_s = ''
            for ref in refs:
                result_s += self.get_string(ref)
            return result_s
        else:
            assert False

# observations from running cl.exe + cvdump.exe:
# the length of symbol varies 238 - 266 => data varies 232 - 260
#
# Since all substrings are null-terminated,
# MAX_LEN = 259 (260 with null).
# MAX_PADDING = \x00\xf3\xf2\xf1 =>
# MIN_LEN = MIN_DATA - MAXPADDING = 228
MAX_LEN = 259
MIN_LEN = 228
# https://github.com/google/syzygy/blob/30b171f90991d6332499da77309c8c1a6d931984/third_party/microsoft-pdb-copy/files/cvinfo.h#L22
# https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/include/mapfile.h#L34
class BuildInfo(object):
    # TYPES_SHIFT
    def __init__(self, offset, workdir, build_tool, source_file, pdb, args):
        self.offset = offset
        self.workdir = workdir
        self.build_tool = build_tool
        self.source_file = source_file
        self.pdb = pdb
        self.args = args

    def patch(self):
        self.workdir = self.p(self.workdir)
        self.build_tool = self.p(self.build_tool)
        self.source_file = self.p(self.source_file)
        self.pdb = self.p(self.pdb)
        self.args = self.p(self.args)

    def serialize(self):
        refs = [0] * 5
        self.symbols = []

        workdir_strings = self.split(self.workdir)
        refs[0] = self.store_strings(workdir_strings)

        build_tool_strings = self.split(self.build_tool)
        refs[1] = self.store_strings(build_tool_strings)

        args_strings = self.split(self.args)
        refs[4] = self.store_strings(args_strings)

        source_file_strings = self.split(self.source_file)
        refs[2] = self.store_strings(source_file_strings)

        pdb_strings = self.split(self.pdb)
        refs[3] = self.store_strings(pdb_strings)

        leaf = BuildInfoLeafEx(refs)
        self.symbols.append(leaf)

    def store_strings(self, ss):
        if len(ss) == 1:
            return self.store_string(ss[0])
        else:
            ref1 = self.store_subst_list(ss[:-1])
            ref2 = self.store_string(ss[-1], ref1)
            return ref2


    def store_subst_list(self, ss):
        new_refs = []
        for s in ss:
            new_ref = self.store_string(s)
            new_refs.append(new_ref)
        new_ref = TYPES_SHIFT + self.offset + len(self.symbols)
        leaf = SubstringLeafEx(new_refs)
        self.symbols.append(leaf)
        return new_ref


    def store_string(self, s, ref=0):
        new_ref = TYPES_SHIFT + self.offset + len(self.symbols)
        leaf = StringLeafEx(s, ref)
        self.symbols.append(leaf)
        return new_ref

    def split(self, s):
        if len(s) < MAX_LEN:
            return [s]
        else:
            space_i = s.find(' ', MIN_LEN, MAX_LEN)
            if space_i != -1:
                return [s[:space_i]] + self.split(s[space_i:])
            else:
                return [s[:MAX_LEN]] + self.split(s[MAX_LEN:])

    def p(self, s):
        global s1, s2, s11, s21
        if s.find(s1) != -1:
            return s.replace(s1, s2)

        if s.find(s11) != -1:
            return s.replace(s11, s21)
        return s


class Leaf(object):
    def get_leaf_id(self):
        leaf_id, = struct.unpack_from('<H', self.data, 2)
        return leaf_id

    def get_len(self):
        leaf_len, = struct.unpack_from('<H', self.data, 0)
        return leaf_len

class LeafGeneric(Leaf):
    def __init__(self, data):
        self.data = data

    def dump(self, id):
        pass

    def patched_result(self, data_output):
        data_output.fromstring(self.data)


class BuildInfoLeaf(Leaf):
    def __init__(self, data):
        self.data = data

    def dump(self, id):
        print '   --------'
        print '   {0}'.format(hex(id))
        count, = struct.unpack_from('<H', self.data, 4)  # 2
        assert count == 5
        print '             |LF_BUILDINFO: count:{0}'.format(count)
        # references
        for i in range(0, count):
            ref, = struct.unpack_from('<I', self.data, 6 + i * 4)
            print '             |LF_BUILDINFO: ref:{0}'.format(hex(ref))

    def patched_result(self, data_output):
        data_output.fromstring(self.data)

    def get_ids(self):
        ids = []
        for i in range(0, 5):
            ref, = struct.unpack_from('<I', self.data, 6 + i * 4)
            ids.append(ref)
        return ids

class BuildInfoLeafEx(Leaf):
    def __init__(self, refs):
        self.refs = refs

    def dump(self, id):
        print '   --------'
        print '   {0}'.format(hex(id))
        count, = struct.unpack_from('<H', self.data, 4)  # 2
        assert count == 5
        print '             |LF_BUILDINFO: count:{0}'.format(count)
        # references
        for i in range(0, count):
            ref, = struct.unpack_from('<I', self.data, 6 + i * 4)
            print '             |LF_BUILDINFO: ref:{0}'.format(hex(ref))

    def patched_result(self, data_output):
        lennn = 6 + len(self.refs) * 4  # type(2), size(2), len*data(4)
        data_output.fromstring(struct.pack('<H', lennn))
        data_output.fromstring(struct.pack('<H', LF_BUILDINFO))
        data_output.fromstring(struct.pack('<H', len(self.refs)))
        for ref in self.refs:
            data_output.fromstring(struct.pack('<I', ref))
        data_output.fromstring('\xf2\xf1')


class StringLeaf(Leaf):
    def __init__(self, data):
        self.data = data

    def dump(self, id):
        ref, = struct.unpack_from('<I', self.data, 4)
        s = self.data[8:]
        s_len = len(s)
        assert (s_len % 4) == 0
        print '   --------'
        print '   {0}'.format(hex(id))
        print '   LF_STRING_ID'
        print '             |substringref:{0}'.format(hex(ref))
        print '             |s:{0}'.format((s,))

    def patched_result(self, data_output):
        prefix = self.data[0:8]
        s = self.data[8:]

        # s_len, typ

        result = s
        end = s.find('\x00')

        if end != -1:
            result = result[0:end + 1]

        if result.find(s1) != -1:
            result = result.replace(s1, s2)

        if result.find(s11) != -1:
            result = result.replace(s11, s21)

        ln = len(result)
        if (ln % 4) != 0:
            padding = 4 - (ln % 4)
            delta = '\xf3\xf2\xf1'[-padding:]
            result += delta

        # len, type, ref
        data_output.fromstring(struct.pack('<H', len(result) + 6))
        data_output.fromstring(prefix[2:4]) # type
        data_output.fromstring(prefix[4:8]) # ref (4)
        data_output.fromstring(result)

    def get_string(self):
        s = self.data[8:]
        end = s.find('\x00')
        if end != -1:
            s = s[0:end]
        else:
            # always zero-terminated
            assert False
        l = len(s)
        if len(s)>200:
            print s
        return s

    def get_ref(self):
        ref, = struct.unpack_from('<I', self.data, 4)
        return ref

class StringLeafEx(Leaf):
    def __init__(self, s, ref=0):
        self.s = s
        self.ref = ref

    def dump(self, id):
        ref, = struct.unpack_from('<I', self.data, 4)
        s = self.data[8:]
        s_len = len(s)
        assert (s_len % 4) == 0
        print '   --------'
        print '   {0}'.format(hex(id))
        print '   LF_STRING_ID'
        print '             |substringref:{0}'.format(hex(ref))
        print '             |s:{0}'.format((s,))

    def patched_result(self, data_output):
        s = self.s

        result = s + '\x00'
        ln = len(result)
        if (ln % 4) != 0:
            padding = 4 - (ln % 4)
            delta = '\xf3\xf2\xf1'[-padding:]
            result += delta

        sub_output = array.array('b')
        sub_output.fromstring(result)

        # len, type, ref
        data_output.fromstring(struct.pack('<H', len(result) + 6))
        data_output.fromstring(struct.pack('<H', LF_STRING_ID))
        data_output.fromstring(struct.pack('<I', self.ref))
        data_output.fromstring(result)



class SubstringLeaf(Leaf):
    def __init__(self, data):
        self.data = data

    def dump(self, id):
        count, = struct.unpack_from('<I', self.data, 4)  # 4
        print '   --------'
        print '   {0}'.format(hex(id))
        print '             |LF_SUBSTR_LIST: count:{0}'.format(count)
        # references
        for i in range(0, count):
            ref, = struct.unpack_from('<I', self.data, 8 + i * 4)
            print '             |LF_SUBSTR_LIST: ref:{0}'.format(hex(ref))

    def patched_result(self, data_output):
        data_output.fromstring(self.data)

    def get_refs(self):
        count, = struct.unpack_from('<I', self.data, 4)  # 4
        refs = []
        for i in range(0, count):
            ref, = struct.unpack_from('<I', self.data, 8 + i * 4)
            refs.append(ref)
        return refs

class SubstringLeafEx(Leaf):
    def __init__(self, refs):
        self.refs = refs

    def dump(self, id):
        count, = struct.unpack_from('<I', self.data, 4)  # 4
        print '   --------'
        print '   {0}'.format(hex(id))
        print '             |LF_SUBSTR_LIST: count:{0}'.format(count)
        # references
        for i in range(0, count):
            ref, = struct.unpack_from('<I', self.data, 8 + i * 4)
            print '             |LF_SUBSTR_LIST: ref:{0}'.format(hex(ref))

    def patched_result(self, data_output):
        lennn = 6 + len(self.refs) * 4 # type(2), size(4), len*data(4)
        data_output.fromstring(struct.pack('<H', lennn))
        data_output.fromstring(struct.pack('<H', LF_SUBSTR_LIST))
        data_output.fromstring(struct.pack('<I', len(self.refs)))
        for ref in self.refs:
            data_output.fromstring(struct.pack('<I', ref))


# returns pairs (section_header, data) - where data to modify
def dump_sections(data, section_headers):
    section_results = []
    for section_header in section_headers:
        section_result = dump_section(data, section_header)
        section_results.append(section_result)
    return section_results


def dump_section(data, section_header):
    if section_header.name == '.debug$S':
        sig, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data)
        assert sig == 4
        pointer = 4
        to_change = False
        subsections = []
        while pointer < section_header.size_of_raw_data:

            xxx_start = section_header.ptr_to_raw_data + pointer
            print "START: {0}".format(hex(xxx_start))

            if (pointer % 4) != 0:
                padding = 4 - (pointer % 4)
                pointer += padding
            if pointer == section_header.size_of_raw_data:
                break

            subsection_start = pointer
            subsection_type, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data + pointer)
            subsection_type_len = 4
            pointer += subsection_type_len

            subsection_len, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data + pointer)
            subsection_len_len = 4
            pointer += subsection_len_len

            prefix_len = subsection_type_len + subsection_len_len

            # subsection includes type and len!!
            subsection = data[
                         section_header.ptr_to_raw_data + subsection_start : section_header.ptr_to_raw_data + subsection_start + subsection_len + 8]

            assert subsection_len != 0

            if subsection_type == DEBUG_S_SYMBOLS:

                ibSym = 8
                left = subsection_len
                to_change_this = False
                symbols = []
                while left > 0:

                    reclen, = struct.unpack_from('<H', subsection, ibSym)  # 2
                    symbolData = subsection[ibSym: ibSym + reclen + 2]
                    type, = struct.unpack_from('<H', subsection, ibSym + 2)  # 2
                    type_len = 2

                    symbol = None
                    if type == S_OBJNAME:
                        to_change_this = True
                        to_change = True
                        signature = struct.unpack_from('<I', symbolData, 4)
                        signature_len = 4
                        slen = reclen - signature_len - type_len  # (type, signature)
                        fmt = '{0}s'.format(slen)
                        name, = struct.unpack_from(fmt, symbolData, 8)
                        # null terminated
                        #print '    S_OBJNAME: {0}'.format(name)
                        # includes reclen
                        # TODO - remove reclen, remove type - directly in constructor
                        symbol = ObjNameSymbol(symbolData)
                    elif type == S_BUILDINFO:
                        id, = struct.unpack_from('<I', symbolData, 4)
                        #print '    S_BUILDINFO: {0}'.format(hex(id))
                        to_change_this = True
                        to_change = True
                        symbol = BuildInfoSymbol(symbolData)
                    else:
                        symbol = GenericSymbol(symbolData)
                    symbols.append(symbol)
                    ibSym += 2 + reclen  # type
                    left -= (2 + reclen)
                if to_change_this:
                    print "DEBUG_S_SYMBOLS: {0}".format(hex(xxx_start))
                    subsections.append(DebugSymbolsSubsection(subsection_type, subsection_len, symbols))
                else:
                    print "OTHER: {0}".format(hex(xxx_start))
                    subsections.append(DebugGenericSubsection(subsection_type, subsection_len, subsection[prefix_len:]))

            elif subsection_type == DEBUG_S_FRAMEDATA:
                print "DEBUG_S_FRAMEDATA: {0}".format(hex(xxx_start))
                # easy
                ibSym = 8
                assert subsection_len == 36

                # TODO reading in cycle
                to_change = True
                subsections.append(DebugFramedataSubsection(subsection_type, subsection_len, subsection[prefix_len:]))
            elif subsection_type == DEBUG_S_STRINGTABLE:
                print "DEBUG_S_STRINGTABLE: {0}".format(hex(xxx_start))
                to_change = True
                subsections.append(DebugStringTableSubsection(subsection_type, subsection_len, subsection[prefix_len:]))
            elif subsection_type == DEBUG_S_FILECHKSMS:
                print "DEBUG_S_FILECHKSMS: {0}".format(hex(xxx_start))
                ibSym = 8
                left = subsection_len
                while left > 0:
                    my_data = subsection[ibSym:ibSym + 24]
                    offset, = struct.unpack_from('<I', my_data, 0)
                    #print '     oFFSET: {0}'.format(hex(offset))
                    ibSym += 24
                    left -= 24
                to_change = True
                subsections.append(DebugFileChkSumSubsection(subsection_type, subsection_len, subsection[8:]))
            else:
                print "OTHER: {0}".format(hex(xxx_start))
                subsections.append(DebugGenericSubsection(subsection_type, subsection_len, subsection[8:]))

            pointer = pointer + subsection_len

        if to_change:
            return DebugSection(subsections)
        else:
            return None

    elif section_header.name == '.debug$T':
        sig, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data)

        assert sig == 4

        pointer = 0
        pointer += 4  # sig
        index = 0x1000
        leaves = []
        while pointer < section_header.size_of_raw_data:
            # padding assertions
            assert (pointer % 4) == 0
            # len(2), type(2)
            # the length of s_data without s_len field
            s_len, = struct.unpack_from('<H', data, section_header.ptr_to_raw_data + pointer)
            piece = data[section_header.ptr_to_raw_data + pointer: section_header.ptr_to_raw_data + pointer + s_len + 2]
            if s_len > 200:
                print piece
            #print '             {0} slen: {1}'.format(hex(index), s_len)

            pointer += 2  # s_len
            leaf, = struct.unpack_from('<H', data, section_header.ptr_to_raw_data + pointer)

            # s_len, ref
            if leaf == LF_STRING_ID:
                leaves.append(StringLeaf(piece))
            elif leaf == LF_BUILDINFO:
                leaves.append(BuildInfoLeaf(piece))
            elif leaf == LF_SUBSTR_LIST:
                leaves.append(SubstringLeaf(piece))
            else:
                leaves.append(LeafGeneric(piece))

            pointer += s_len
            index += 1

        types_section = TypesSection(leaves)
        types_section.mkBuildInfo()
        return types_section

    return None

def process(sections, data, results, data_output):
    """modifies sections, returns a number of removed bytes and a list of pairs (start, end) to copy"""
    removed_bytes = 0
    to_copy = []
    # SECTION_HEADERS_START = 20
    # SECTION_HEADER_SIZE = 40

    start = SECTION_HEADERS_START + SECTION_HEADER_SIZE*len(sections)
    assert len(data_output) == 0
    for i in range(0, len(sections)):
        section = sections[i]
        result = results[i]

        ptr_to_raw_data = section.ptr_to_raw_data
        ptr_to_relocations = section.ptr_to_relocations
        new_ptr_to_raw_data = len(data_output)
        assert section.ptr_to_linenumbers == 0
        size_of_relocations = section.number_of_relocations * RELOCATION_SIZE

        make_relocations = False
        if result:
            result.patched_result(data_output)
            # changing
            section.ptr_to_raw_data = new_ptr_to_raw_data + start
            section.size_of_raw_data = len(data_output) - new_ptr_to_raw_data
            if section.name == '.debug$S' and RELOCATION_SHIFT[2]:
                make_relocations = True
                RELOCATION_SHIFT[2] = False
        else:
            if section.ptr_to_raw_data > 0 and section.size_of_raw_data > 0:
                section.ptr_to_raw_data = new_ptr_to_raw_data + start
                data_output.fromstring(data[ptr_to_raw_data: ptr_to_raw_data + section.size_of_raw_data])
        # section.ptr_to_raw_data = len(data_output)
        # copying relocations

        if section.number_of_relocations > 0:
            new_ptr_to_relocations = len(data_output)
            relocations_data = data[ptr_to_relocations: ptr_to_relocations + size_of_relocations]
            if make_relocations:
                shift = RELOCATION_SHIFT[1]
                print shift
                relocation_output = array.array('b')
                for ri in range(0, section.number_of_relocations):
                    rdata = relocations_data[ri*RELOCATION_SIZE: (ri+1)*RELOCATION_SIZE]
                    rva, = struct.unpack_from('<I', rdata)
                    rva += shift
                    relocation_output.fromstring(struct.pack('<I', rva))
                    relocation_output.fromstring(rdata[4:])
                data_output.extend(relocation_output)
            else:
                data_output.fromstring(relocations_data)

            section.ptr_to_relocations = new_ptr_to_relocations + start


    return removed_bytes, to_copy


def write_section_headers(output, sections):
    for section in sections:
        section.write(output)


def write_symbol_table(output, data, pointer_to_symbol_table, number_of_symbols, sections_headers, results):
    aux_symbols = 0
    change_next = False
    section = None
    for i in range(0, number_of_symbols):
        start = pointer_to_symbol_table + SYMBOL_SIZE * i
        symbol = data[start: start + SYMBOL_SIZE]
        if aux_symbols == 0:
            aux_symbols, = struct.unpack_from(AUX_SYMBOLS_FORMAT, symbol, AUX_SYMBOLS_OFFSET)
            section, = struct.unpack_from(SECTION_SYMBOL_FORMAT, symbol, SECTION_SYMBOL_OFFSET)
            output.fromstring(symbol)
            if section > 0 and section <= len(sections_headers):
                if (results[section-1]):
                    change_next = True
                    if aux_symbols != 1:
                        assert False
        else:
            aux_symbols -= 1
            if change_next:
                output.fromstring(struct.pack('<I', sections_headers[section - 1].size_of_raw_data))
                output.fromstring(symbol[4:])
                change_next = False
            else:
                output.fromstring(symbol)


mapping = {}
s1 = 'Y:\\experiments\\yyyyyyyyyyyyyyyyyy'
s2 = 'Y:\\experiments\\yyyyyyyyyyyyyyyyyy'
s11 = s1.lower()
s21 = s2.lower()


def patch(input_file, out_file, original_dir, canonical_dir):
    global s1, s2, s11, s21
    s1 = original_dir
    s2 = canonical_dir
    s11 = s1.lower()
    s21 = s2.lower()

    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    output = array.array('b')
    data_output = array.array('b')

    header = FileHeader(data)
    old_pointer_to_symbol_table = header.pointer_to_symbol_table
    section_headers = read_section_headers(data, header.number_of_sections)
    to_copy_string_section = header.pointer_to_symbol_table + (SYMBOL_SIZE * header.number_of_symbols), len(data)

    results = dump_sections(data, section_headers)
    for result in results:
        if result:
            result.dump()
            pass

    for result in results:
        if result:
            result.patch()

    # stage1: patching debug$S section
    # 1) S_OBJNAME
    # 2) string table
    # 3) patch checksum

    process(section_headers, data, results, data_output)

    startX, endX = to_copy_string_section
    #data_output.fromstring(data[old_pointer_to_symbol_table:start])
    new_pointer_to_symbol_table = SECTION_HEADERS_START + SECTION_HEADER_SIZE*header.number_of_sections + len(data_output)

    header.pointer_to_symbol_table = new_pointer_to_symbol_table
    write_symbol_table(data_output, data, old_pointer_to_symbol_table, header.number_of_symbols, section_headers, results)
    data_output.fromstring(data[startX:endX])

    header.write(output)
    write_section_headers(
        output,
        section_headers)

    total_output = output + data_output
    with open(out_file, 'wb') as ofile:
        total_output.tofile(ofile)

    print "TOCOPY: {0},{1}".format(hex(startX), hex(endX))

import optparse
def main(args=None):
    parser = optparse.OptionParser()
    parser.add_option("--input-object", dest="input_object",
                      help="input object file (implies --output-object)", metavar="FILE")
    parser.add_option("--output-object", dest="output_object",
                      help="output object file", metavar="FILE")
    parser.add_option("--original-dir", dest="original_dir",
                      help="original directory", metavar="DIR")
    parser.add_option("--canonical-dir", dest="canonical_dir",
                      help="canonical directory", metavar="DIR")

    (options, args) = parser.parse_args(args)

    if options.input_object and options.output_object and options.original_dir and options.canonical_dir:
        patch(options.input_object, options.output_object, options.original_dir, options.canonical_dir)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
