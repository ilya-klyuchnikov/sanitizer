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

    def write(self, output, removed_bytes):
        output.fromstring(
            struct.pack(MACHINE_FORMAT, self.machine))
        output.fromstring(
            struct.pack(NUMBER_OF_SECTIONS_FORMAT, self.number_of_sections))
        output.fromstring(
            struct.pack(TIME_DATE_STAMP_FORMAT, self.time_date_stamp)) # SIC
        output.fromstring(
            struct.pack(POINTER_TO_SYMBOL_TABLE_FORMAT, self.pointer_to_symbol_table - removed_bytes))
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
    removed_pieces = []
    removed_bytes = 0
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
        # we assert no line number for now!
        # TODO - check that this is 0
        number_of_line_numbers, = struct.unpack_from('<h', data, this_start + 34)
        assert number_of_line_numbers == 0

        if section_i in sections_to_strip:
            if size_of_raw_data > 0:
                removed_pieces.append((ptr_to_raw_data, size_of_raw_data))
            if number_of_relocations > 0:
                removed_pieces.append((ptr_to_relocations, number_of_relocations * RELOCATION_SIZE))

        if section_i in sections_to_strip:
            removed_bytes = removed_bytes + size_of_raw_data + (number_of_relocations * RELOCATION_SIZE)
            sections.append((0, max(ptr_to_relocations - removed_bytes, 0)))
        else:
            sections.append((max(ptr_to_raw_data - removed_bytes, 0), max(ptr_to_relocations - removed_bytes, 0)))

    return sections, removed_pieces, removed_bytes


def write_section_headers(output, data, sections, number_of_sections):
    for section_i in range(0, number_of_sections):
        section = sections[section_i]
        if section:
            this_start = SECTION_HEADERS_START + section_i * SECTION_HEADER_SIZE
            output.fromstring(data[this_start : this_start + 16])
            ptr_to_raw_data, ptr_to_relocations = section
            if ptr_to_raw_data > 0:
                output.fromstring(data[this_start + 16: this_start + 20])
            else:
                output.fromstring(struct.pack('<I', 0))
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


def write_data(output, data, removed_pieces, begin_index, end_index):
    def stripped(i):
        for start, size in removed_pieces:
            if start <= i < start + size:
                return True
        return False

    for i in range(begin_index, end_index):
        if not stripped(i):
            output.fromstring(data[i])


def write_symbol_table(RESULT, data, pointer_to_symbol_table, number_of_symbols, sections_to_strip):
    aux_symbols = 0
    removing_symbol = False
    for i in range(0, number_of_symbols):
        start = pointer_to_symbol_table + SYMBOL_SIZE * i
        if aux_symbols == 0:
            aux_symbols, = struct.unpack_from('<B', data, start + 17)
            section, = struct.unpack_from('<h', data, start + 12)
            if section > 0:
                removing_symbol = (section - 1) in sections_to_strip
                RESULT.fromstring(data[start : start + 12])
                RESULT.fromstring(struct.pack('<h', section))
                RESULT.fromstring(data[start + 14 : start + SYMBOL_SIZE])
            else:
                removing_symbol = False
                RESULT.fromstring(data[start : start + SYMBOL_SIZE])
        else:
            aux_symbols -= 1
            if removing_symbol:
                print 'PROCESSING AUX SYMBOL' # making it 00000
                RESULT.fromstring(str(bytearray(18)))
            else:
                RESULT.fromstring(data[start : start + SYMBOL_SIZE])


def strip(input_file, out_file):
    """
    Strips a COFF file produced by a MSVC compiler, removing non-deterministic information.

    """
    # http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx

    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    RESULT = array.array('b')

    header = FileHeader(data)
    # sorted_by_second = sorted(data, key=lambda tup: tup[1])

    # section mapping - old -> new (zero based)
    sections_to_strip = find_sections_to_strip(data, header.number_of_sections)
    sections, removed_pieces, removed_bytes = process(data, header.number_of_sections, sections_to_strip)

    header.time_date_stamp = 0
    #header.pointer_to_symbol_table = header.pointer_to_symbol_table - removed_bytes

    header.write(
        RESULT,
        removed_bytes)
    write_section_headers(
        RESULT,
        data,
        sections,
        header.number_of_sections)
    write_data(
        RESULT,
        data,
        removed_pieces,
        SECTION_HEADERS_START + header.number_of_sections*SECTION_HEADER_SIZE,
        header.pointer_to_symbol_table)
    write_symbol_table(
        RESULT,
        data,
        header.pointer_to_symbol_table,
        header.number_of_symbols,
        sections_to_strip)

    # copying string section of symbol table
    RESULT.fromstring(
        data[header.pointer_to_symbol_table + SYMBOL_SIZE * header.number_of_symbols:]
    )

    with open(out_file, 'wb') as ofile:
        RESULT.tofile(ofile)
