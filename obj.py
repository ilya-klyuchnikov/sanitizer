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


def process(sections):
    """modifies sections, returns a number of removed bytes and a list of pairs (start, end) to copy"""
    removed_bytes = 0
    to_copy = []
    for section in sections:
        assert section.ptr_to_linenumbers == 0
        size_of_relocations = section.number_of_relocations * RELOCATION_SIZE
        if section.should_strip_section():
            removed_bytes = removed_bytes + section.size_of_raw_data + size_of_relocations
            section.ptr_to_raw_data = 0
            section.ptr_to_relocations = 0
            section.size_of_raw_data = 0
        else:
            if section.ptr_to_raw_data > 0 and section.size_of_raw_data > 0:
                to_copy.append((section.ptr_to_raw_data, section.ptr_to_raw_data + section.size_of_raw_data))
            if section.number_of_relocations > 0:
                to_copy.append((section.ptr_to_relocations, section.ptr_to_relocations + size_of_relocations))
            section.ptr_to_raw_data = max(section.ptr_to_raw_data - removed_bytes, 0)
            section.ptr_to_relocations = max(section.ptr_to_relocations - removed_bytes, 0)

    return removed_bytes, to_copy


def write_section_headers(output, sections):
    for section in sections:
        section.write(output)


def write_symbol_table(output, data, pointer_to_symbol_table, number_of_symbols, sections_headers):
    aux_symbols = 0
    removing_symbol = False
    for i in range(0, number_of_symbols):
        start = pointer_to_symbol_table + SYMBOL_SIZE * i
        symbol = data[start: start + SYMBOL_SIZE]
        if aux_symbols == 0:
            aux_symbols, = struct.unpack_from(AUX_SYMBOLS_FORMAT, symbol, AUX_SYMBOLS_OFFSET)
            section, = struct.unpack_from(SECTION_SYMBOL_FORMAT, symbol, SECTION_SYMBOL_OFFSET)
            if section > 0:
                removing_symbol = sections_headers[section - 1].should_strip_section()
            else:
                removing_symbol = False
            output.fromstring(symbol)
        else:
            aux_symbols -= 1
            if removing_symbol:
                output.extend(bytearray(SYMBOL_SIZE))
            else:
                output.fromstring(symbol)


def strip(input_file, out_file):
    """
    Strips a COFF file produced by a MSVC compiler, removing non-deterministic information.

    """

    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    output = array.array('b')

    header = FileHeader(data)
    # sorted_by_second = sorted(data, key=lambda tup: tup[1])

    old_pointer_to_symbol_table = header.pointer_to_symbol_table
    section_headers = read_section_headers(data, header.number_of_sections)
    removed_bytes, to_copy = process(section_headers)
    to_copy_string_section = [
        (header.pointer_to_symbol_table + SYMBOL_SIZE * header.number_of_symbols, len(data)),
    ]

    header.time_date_stamp = 0
    header.pointer_to_symbol_table -= removed_bytes

    header.write(output)
    write_section_headers(
        output,
        section_headers)

    for start, end in to_copy:
        output.fromstring(data[start:end])

    write_symbol_table(
        output,
        data,
        old_pointer_to_symbol_table,
        header.number_of_symbols,
        section_headers)

    for start, end in to_copy_string_section:
        output.fromstring(data[start:end])

    with open(out_file, 'wb') as ofile:
        output.tofile(ofile)
