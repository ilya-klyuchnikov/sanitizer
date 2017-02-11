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

def dump_sections(data, section_headers):
    fNoCvSig = False
    sig = None
    for section_header in section_headers:
        if section_header.name == '.debug$S':
            print '.debug$S'
            if not fNoCvSig:
                sig, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data)
                if sig == 4:
                    ib = 4
                    while ib < section_header.size_of_raw_data:
                        if ((ib % 4) != 0):
                            cb = 4 - (ib % 4)
                            ib += cb
                        if ib == section_header.size_of_raw_data:
                            break
                        sst, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data + ib)
                        ib += 4
                        # length of section WTF!
                        cb, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data + ib)
                        ib += 4
                        if cb == 0:
                            cb = section_header.size_of_raw_data - ib
                        # printing debug symbols
                        if sst == DEBUG_S_SYMBOLS:
                            print '  SYMBOLS'
                            ibSym = ib
                            left = cb
                            while left > 0:

                                reclen, = struct.unpack_from('<H', data, section_header.ptr_to_raw_data + ibSym)
                                type, = struct.unpack_from('<H', data, section_header.ptr_to_raw_data + ibSym + 2)

                                print '    ibsym: {0}'.format(hex(ibSym))
                                if type == S_OBJNAME:
                                    signature = struct.unpack_from('<I', data, section_header.ptr_to_raw_data + ibSym + 4)
                                    slen = reclen - 4 - 2 # (type, signature)
                                    fmt = '{0}s'.format(slen)
                                    name, = struct.unpack_from(fmt, data, section_header.ptr_to_raw_data + ibSym + 8)
                                    # null terminated
                                    print '    S_OBJNAME: {0}'.format(name)

                                else:
                                    print '    UNKNOWN SYMBOL'

                                ibSym += 2 + reclen
                                left -= (2 + reclen)

                        if sst == DEBUG_S_FRAMEDATA:
                            ibSym = ib
                            print '  FRAMEDATA'
                            rva = struct.unpack_from('<I', data, section_header.ptr_to_raw_data + ibSym)

                            # TODO reading in cycle
                            # the size of data - 32
                            pointer, = struct.unpack_from('<I', data, section_header.ptr_to_raw_data + ibSym + 4 + 5*4)
                            print '    pointer: {0}'.format(hex(pointer))

                        if sst == DEBUG_S_STRINGTABLE:
                            print '  STRINGTABLE'
                            fmt = '{0}s'.format(cb)
                            table, = struct.unpack_from(fmt, data, section_header.ptr_to_raw_data + ib)
                            strs = table.split('\0')
                            table2 = '\0'.join(strs)
                            i = table.find('$T0 $ebp')
                            assert table == table2
                            print table
                            print strs
                            print hex(i)

                        if sst == DEBUG_S_FILECHKSMS:
                            print '  FILECHKSMS'
                            ibSym = ib
                            left = cb
                            while left > 0:
                                my_data = data[section_header.ptr_to_raw_data + ibSym:section_header.ptr_to_raw_data + ibSym + 24]
                                offset, = struct.unpack_from('<I', my_data, 0)
                                print '     oFFSET: {0}'.format(hex(offset))
                                ibSym += 24
                                left -= 24

                        ib = ib + cb

        if section_header.name == '.debug$T':
            print '.debug$T'
            ib = 0
            # sig
            ib = 4
            while ib < section_header.size_of_raw_data:
                s_len, = struct.unpack_from('<H', data, section_header.ptr_to_raw_data + ib)
                print 'slen: {}'.format(s_len)
                ib += 2
                s_data = data[section_header.ptr_to_raw_data + ib : section_header.ptr_to_raw_data + ib + s_len]
                print s_data
                ib += s_len



def dump(input_file):
    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    header = FileHeader(data)
    old_pointer_to_symbol_table = header.pointer_to_symbol_table
    section_headers = read_section_headers(data, header.number_of_sections)
    dump_sections(data, section_headers)


#dump('/Volumes/C/workspace/main.obj')
dump('main-2.obj')
