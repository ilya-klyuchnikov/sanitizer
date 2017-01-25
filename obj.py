import struct
import array

# 3.3. COFF File Header (Object and Image)
MACHINE_OFFSET = 0
MACHINE_FORMAT = '<h'

NUMBER_OF_SECTIONS_OFFSET = 2
NUMBER_OF_SECTIONS_FORMAT = '<h'

TIME_DATE_STAMP_OFFSET = 6
TIME_DATE_STAMP_FORMAT = '<I'

POINTER_TO_SYMBOL_TABLE_OFFSET = 8
POINTER_TO_SYMBOL_TABLE_FORMAT = '<I'

NUMBER_OF_SYMBOLS_OFFSET = 12
NUMBER_OF_SYMBOLS_FORMAT = '<I'

SIZE_OF_OPTIONAL_HEADER_OFFSET = 16
SIZE_OF_OPTIONAL_HEADER_FORMAT = '<h'

CHARACTERISTICS_OFFSET = 18
CHARACTERISTICS_FORMAT = '<h'

# COFF File Header
COFF_FILE_HEADER_SIZE = 20

# 4. Section Table (Section Headers)
SECTION_HEADERS_START = 20
SECTION_HEADER_SIZE = 40
SECTION_HEADER_CHARACTERISTICS_OFFSET = 36
SECTION_HEADER_CHARACTERISTICS_FORMAT = '<I'

# 5.2. COFF Relocations (Object Only)
RELOCATION_SIZE = 10
# see spec
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_LNK_COMDAT = 0x00001000
# https://docs.python.org/2/library/struct.html

SYMBOL_SIZE = 18


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


def should_strip_section(sec_characteristics):
    # IMAGE_SCN_LNK_COMDAT - debug$S may have IMAGE_SCN_LNK_COMDAT for imported functions
    return (sec_characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0) and (sec_characteristics & IMAGE_SCN_LNK_COMDAT == 0)


def find_sections_to_strip(data, number_of_sections):
    sections = []
    for section_i in range(0, number_of_sections):
        sec_characteristics, = struct.unpack_from(
            SECTION_HEADER_CHARACTERISTICS_FORMAT,
            data,
            SECTION_HEADERS_START + (section_i * SECTION_HEADER_SIZE) + SECTION_HEADER_CHARACTERISTICS_OFFSET
        )
        if should_strip_section(sec_characteristics):
            sections.append(section_i)
    return set(sections)


def process(data, number_of_sections, sections_to_strip):
    sections = []
    removed_bytes = 0
    to_copy = []
    for section_i in range(0, number_of_sections):
        this_start = SECTION_HEADERS_START + section_i * SECTION_HEADER_SIZE
        size_of_raw_data, = struct.unpack_from('<I', data, this_start + 16)
        ptr_to_raw_data, = struct.unpack_from('<I', data, this_start + 20)
        ptr_to_relocations, = struct.unpack_from('<I', data, this_start + 24)
        # 5.3. COFF Line Numbers (Deprecated)
        # COFF line numbers are no longer produced and, in the future, will not be consumed.

        ptr_to_line_numbers, = struct.unpack_from('<I', data, this_start + 28)
        assert ptr_to_line_numbers == 0

        number_of_relocations, = struct.unpack_from('<h', data, this_start + 32)
        number_of_line_numbers, = struct.unpack_from('<h', data, this_start + 34)
        assert number_of_line_numbers == 0

        size_of_relocations = number_of_relocations * RELOCATION_SIZE

        if section_i in sections_to_strip:
            removed_bytes = removed_bytes + size_of_raw_data + (size_of_relocations)
            sections.append((0, 0, 0))
        else:
            sections.append((max(ptr_to_raw_data - removed_bytes, 0), max(ptr_to_relocations - removed_bytes, 0), size_of_raw_data))

        if section_i not in sections_to_strip:
            if size_of_raw_data > 0 and ptr_to_raw_data > 0:
                to_copy.append((ptr_to_raw_data, ptr_to_raw_data + size_of_raw_data))
            if number_of_relocations > 0:
                to_copy.append((ptr_to_relocations, ptr_to_relocations + size_of_relocations))

    return sections, removed_bytes, to_copy


def write_section_headers(output, data, sections, number_of_sections):
    for section_i in range(0, number_of_sections):
        section = sections[section_i]
        if section:
            this_start = SECTION_HEADERS_START + section_i * SECTION_HEADER_SIZE
            output.fromstring(data[this_start : this_start + 16])
            ptr_to_raw_data, ptr_to_relocations, raw_size = section
            output.fromstring(struct.pack('<I', raw_size))
            # 20 ptr_to_raw_data
            output.fromstring(struct.pack('<I', ptr_to_raw_data))
            # 24 ptr_to_relocations
            output.fromstring(struct.pack('<I', ptr_to_relocations))
            # 28 - ptr_to_line_numbers
            output.fromstring(data[this_start + 28: this_start + 32])
            if ptr_to_relocations > 0:
                output.fromstring(data[this_start + 32: this_start + 34])
            else:
                output.fromstring(struct.pack('<h', 0))
            output.fromstring(data[this_start + 34 : this_start + 40])


def write_symbol_table(output, data, pointer_to_symbol_table, number_of_symbols, sections_to_strip):
    aux_symbols = 0
    removing_symbol = False
    for i in range(0, number_of_symbols):
        start = pointer_to_symbol_table + SYMBOL_SIZE * i
        if aux_symbols == 0:
            aux_symbols, = struct.unpack_from('<B', data, start + 17)
            section, = struct.unpack_from('<h', data, start + 12)
            if section > 0:
                removing_symbol = (section - 1) in sections_to_strip
            else:
                removing_symbol = False
            output.fromstring(data[start : start + SYMBOL_SIZE])
        else:
            aux_symbols -= 1
            if removing_symbol:
                output.fromstring(str(bytearray(18)))
            else:
                output.fromstring(data[start : start + SYMBOL_SIZE])


def strip(input_file, out_file):
    """
    Strips a COFF file produced by a MSVC compiler, removing non-deterministic information.

    """
    # http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx

    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    output = array.array('b')

    header = FileHeader(data)
    # sorted_by_second = sorted(data, key=lambda tup: tup[1])

    old_pointer_to_symbol_table = header.pointer_to_symbol_table
    sections_to_strip = find_sections_to_strip(data, header.number_of_sections)
    sections, removed_bytes, to_copy = process(data, header.number_of_sections, sections_to_strip)
    to_copy_string_section = [
        (header.pointer_to_symbol_table + SYMBOL_SIZE * header.number_of_symbols, len(data)),
    ]

    header.time_date_stamp = 0
    header.pointer_to_symbol_table -= removed_bytes

    header.write(
        output)
    write_section_headers(
        output,
        data,
        sections,
        header.number_of_sections)

    for start, end in to_copy:
        output.fromstring(data[start:end])

    write_symbol_table(
        output,
        data,
        old_pointer_to_symbol_table,
        header.number_of_symbols,
        sections_to_strip)

    for start, end in to_copy_string_section:
        output.fromstring(data[start:end])

    with open(out_file, 'wb') as ofile:
        output.tofile(ofile)
