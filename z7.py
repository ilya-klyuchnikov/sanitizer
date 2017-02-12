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
        return (self.characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0) and (self.characteristics & IMAGE_SCN_LNK_COMDAT == 0)


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

    def patch(self, s1, s2):
        for subsection in self.subsections:
            subsection.patch(s1, s2)

class DebugSubsection(object):
    pass


class DebugGenericSubsection(DebugSubsection):
    def __init__(self, subsection_data):
        self.subsection_data = subsection_data

    def dump(self):
        pass

    def patch(self, s1, s2):
        pass


class DebugSymbolsSubsection(DebugSubsection):
    def __init__(self, symbols):
        self.symbols = symbols

    def dump(self):
        for symbol in self.symbols:
            symbol.dump()

    def patch(self, s1, s2):
        for symbol in self.symbols:
            symbol.patch(s1, s2)


class DebugFramedataSubsection(DebugSubsection):
    def __init__(self, subsection_data):
        self.subsection_data = subsection_data

    def dump(self):
        print '  FRAMEDATA'
        # the size of data - 32
        ppointer, = struct.unpack_from('<I', self.subsection_data, 8 + 4 + 5 * 4)
        print '    pointer: {0}'.format(hex(ppointer))

    def patch(self, s1, s2):
        pass


class DebugStringTableSubsection(DebugSubsection):
    def __init__(self, subsection_data):
        self.subsection_data = subsection_data

    def dump(self):
        print '  STRINGTABLE'
        table = self.subsection_data[8:]
        strs = table.split('\0')
        print strs

    def patch(self, s1, s2):
        table = self.subsection_data[8:]
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

        subst = {}
        for i in range(0, len(ss1)):
            subst[delims[i]] = next_indices[i]
            print '{0} -> {1}'.format(hex(delims[i]), hex(next_indices[i]))

        #print subst



class DebugFileChkSumSubsection(DebugSubsection):
    def __init__(self, subsection_data):
        self.subsection_data = subsection_data

    def dump(self):
        ibSym = 8
        left = len(self.subsection_data) - 8
        print '  FILECHKSMS'
        while left > 0:
            my_data = self.subsection_data[ibSym:ibSym + 24]
            offset, = struct.unpack_from('<I', my_data, 0)
            print '     oFFSET: {0}'.format(hex(offset))
            ibSym += 24
            left -= 24

    def patch(self, s1, s2):
        pass


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


    def patch(self, s1, s2):
        name = self.subsection_data[8:]
        result = name.replace(s1, s2)
        print "   S_OBJNAME: {0} -> {1}".format(name, result)
        pass


class BuildInfoSymbol(Symbol):
    def __init__(self, subsection_data):
        self.subsection_data = subsection_data

    def dump(self):
        reclen, = struct.unpack_from('<H', self.subsection_data, 0)  # 2
        id, = struct.unpack_from('<I', self.subsection_data, 4)
        print '    S_BUILDINFO: {0}'.format(hex(id))

    def patch(self, s1, s2):
        pass


class GenericSymbol(Symbol):
    def __init__(self, subsection_data):
        self.subsection_data = subsection_data

    def dump(self):
        pass

    def patch(self, s1, s2):
        pass


class TypesSection(object):
    def __init__(self, leaves):
        self.leaves = leaves

    def dump(self):
        i = 0x1000
        for leaf in self.leaves:
            leaf.dump(i)
            i += 1

    def patch(self, s1, s2):
        pass

class Leaf(object):
    pass

class LeafGeneric(Leaf):
    def __init__(self, data):
        self.data = data

    def dump(self, id):
        pass

class BuildInfoLeaf(Leaf):
    def __init__(self, data):
        self.data = data

    def dump(self, id):
        print '   --------'
        print '   {0}'.format(hex(id))
        count, = struct.unpack_from('<H', self.data, 4)  # 2
        print '             |LF_BUILDINFO: count:{0}'.format(count)
        # references
        for i in range(0, count):
            ref, = struct.unpack_from('<I', self.data, 6 + i * 4)
            print '             |LF_BUILDINFO: ref:{0}'.format(hex(ref))

class StringLeaf(Leaf):
    def __init__(self, data):
        self.data = data

    def dump(self, id):
        ref, = struct.unpack_from('<I', self.data, 4)
        s = self.data[8:]
        print '   --------'
        print '   {0}'.format(hex(id))
        print '   LF_STRING_ID'
        print '             |substringref:{0}'.format(hex(ref))
        print '             |s:{0}'.format(s)

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

# returns pairs (section_header, data) - where data to modify
def dump_sections(data, section_headers):
    section_results = []
    for section_header in section_headers:
        section_result = dump_section(data, section_header)
        if section_result:
            section_results.append((section_header, section_result))
    return section_results


def dump_section(data, section_header):
    if section_header.name == '.debug$S':
        sig, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data)
        assert sig == 4
        pointer = 4
        to_change = False
        subsections = []
        while pointer < section_header.size_of_raw_data:

            if (pointer % 4) != 0:
                padding = 4 - (pointer % 4)
                pad = data[section_header.ptr_to_raw_data + pointer: section_header.ptr_to_raw_data + pointer + padding]
                pointer += padding
            if pointer == section_header.size_of_raw_data:
                break

            subsection_start = pointer
            subsection_type, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data + pointer)
            pointer += 4

            subsection_len, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data + pointer)
            pointer += 4

            subsection = data[
                         section_header.ptr_to_raw_data + subsection_start: section_header.ptr_to_raw_data + subsection_start + subsection_len + 8]

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
                    subsections.append(DebugSymbolsSubsection(symbols))
                else:
                    subsections.append(DebugGenericSubsection(subsection))

            elif subsection_type == DEBUG_S_FRAMEDATA:
                # easy
                ibSym = 8
                assert subsection_len == 36

                # TODO reading in cycle
                to_change = True
                subsections.append(DebugFramedataSubsection(subsection))
            elif subsection_type == DEBUG_S_STRINGTABLE:
                ibSym = 8
                to_change = True
                subsections.append(DebugStringTableSubsection(subsection))
            elif subsection_type == DEBUG_S_FILECHKSMS:
                #print '  FILECHKSMS'
                ibSym = 8
                left = subsection_len
                while left > 0:
                    my_data = subsection[ibSym:ibSym + 24]
                    offset, = struct.unpack_from('<I', my_data, 0)
                    #print '     oFFSET: {0}'.format(hex(offset))
                    ibSym += 24
                    left -= 24
                to_change = True
                subsections.append(DebugFileChkSumSubsection(subsection))
            else:
                subsections.append(DebugGenericSubsection(subsection))

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
            # the length of s_data
            s_len, = struct.unpack_from('<H', data, section_header.ptr_to_raw_data + pointer)
            piece = data[section_header.ptr_to_raw_data + pointer: section_header.ptr_to_raw_data + pointer + s_len + 2]
            #print '             {0} slen: {1}'.format(hex(index), s_len)
            pointer += 2  # s_len
            leaf, = struct.unpack_from('<H', data, section_header.ptr_to_raw_data + pointer)

            #print '             |leaf:{0}'.format(hex(leaf))
            #print '             |{0}'.format(':'.join(x.encode('hex') for x in piece))
            # print '             |{0}'.format(s_data)
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

        return TypesSection(leaves)

    return None


def dump(input_file, s1, s2):
    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    header = FileHeader(data)
    section_headers = read_section_headers(data, header.number_of_sections)
    results = dump_sections(data, section_headers)
    for header, result in results:
        print '>>>>> {0}'.format(header.name)
        result.dump()

    for header, result in results:
        result.patch(s1, s2)

    # stage1: patching debug$S section
    # 1) S_OBJNAME
    # 2) string table


dump('experiments/01/01.obj', 'Y:\\experiments\\01', 'Y:\\buck\\build')
