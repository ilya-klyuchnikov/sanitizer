import struct
import array

# 3.3. COFF File Header (Object and Image)
NUMBER_OF_SECTIONS_OFFSET = 2
NUMBER_OF_SECTIONS_FORMAT = '<h'
POINTER_TO_SYMBOL_TABLE_OFFSET = 8
POINTER_TO_SYMBOL_TABLE_FORMAT = '<I'
NUMBER_OF_SYMBOLS_OFFSET = 12
NUMBER_OF_SYMBOLS_FORMAT = '<I'
SIZE_OF_OPTIONAL_HEADER_OFFSET = 16
SIZE_OF_OPTIONAL_HEADER_FORMAT = '<h'
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


def strip(input_file, out_file):
    """
    Strips a COFF file produced by a MSVC compiler, removing non-deterministic information.

    """
    # http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx

    ifile = open(input_file, 'rb')
    data = ifile.read()
    ifile.close()

    number_of_sections, = struct.unpack_from(
        NUMBER_OF_SECTIONS_FORMAT,
        data,
        NUMBER_OF_SECTIONS_OFFSET
    )

    pointer_to_symbol_table, = struct.unpack_from(
        POINTER_TO_SYMBOL_TABLE_FORMAT,
        data,
        POINTER_TO_SYMBOL_TABLE_OFFSET
    )

    number_of_symbols, = struct.unpack_from(
        NUMBER_OF_SYMBOLS_FORMAT,
        data,
        NUMBER_OF_SYMBOLS_OFFSET
    )

    size_of_optional_header, = struct.unpack_from(
        SIZE_OF_OPTIONAL_HEADER_FORMAT,
        data,
        SIZE_OF_OPTIONAL_HEADER_OFFSET
    )

    # /GL compilation is not supported
    assert size_of_optional_header == 0

    # sorted_by_second = sorted(data, key=lambda tup: tup[1])

    # section mapping - old -> new (zero based)
    sections_to_strip = find_sections_to_strip(data, number_of_sections)
    sections, removed_pieces, removed_bytes = process(data, number_of_sections, sections_to_strip)

    RESULT = array.array('b')

    RESULT.fromstring(data[0:2])
    RESULT.fromstring(struct.pack('<h', number_of_sections))
    RESULT.fromstring(struct.pack('<I', 0))
    RESULT.fromstring(struct.pack('<I', pointer_to_symbol_table - removed_bytes))
    RESULT.fromstring(struct.pack('<I', number_of_symbols))
    RESULT.fromstring(data[16:20])

    for section_i in range(0, number_of_sections):
        section = sections[section_i]
        if section:
            this_start = SECTION_HEADERS_START + section_i * SECTION_HEADER_SIZE
            RESULT.fromstring(data[this_start : this_start + 16])
            ptr_to_raw_data, ptr_to_relocations = section
            if ptr_to_raw_data > 0:
                RESULT.fromstring(data[this_start + 16: this_start + 20])
            else:
                RESULT.fromstring(struct.pack('<I', 0))
            # 20 ptr_to_raw_data
            RESULT.fromstring(struct.pack('<I', ptr_to_raw_data))
            # 24 ptr_to_relocations
            RESULT.fromstring(struct.pack('<I', ptr_to_relocations))
            # 28 - ptr_to_line_numbers
            RESULT.fromstring(data[this_start + 28: this_start + 32])
            if ptr_to_relocations > 0:
                RESULT.fromstring(data[this_start + 32: this_start + 34])
            else:
                RESULT.fromstring(struct.pack('<h', 0))
            RESULT.fromstring(data[this_start + 34 : this_start + 40])

    def stripped(i):
        for start, size in removed_pieces:
            if start <= i < start + size:
                return True
        return False

    # copying everything up to the symbol table symbol
    for i in range(SECTION_HEADERS_START + number_of_sections*SECTION_HEADER_SIZE, pointer_to_symbol_table):
        if stripped(i):
            pass
        else:
            RESULT.fromstring(data[i])

    aux_symbols = 0
    removing_symbol = False
    # copying symbol table
    for i in range(0, number_of_symbols):
        start = pointer_to_symbol_table + SYMBOL_SIZE * i
        if aux_symbols == 0:
            aux_symbols, = struct.unpack_from('<B', data, start + 17)
            section, = struct.unpack_from('<h', data, start + 12)
            if section > 0:
                removing_symbol = (section - 1) in sections_to_strip
                RESULT.fromstring(data[start : start + 12])
                RESULT.fromstring(struct.pack('<h', section))
                # everything after section
                RESULT.fromstring(data[start + 14 : start + SYMBOL_SIZE])
            else:
                removing_symbol = False
                RESULT.fromstring(data[start : start + SYMBOL_SIZE])
        else:
            aux_symbols -= 1
            if removing_symbol:
                print "PROCESSING AUX SYMBOL"
                RESULT.fromstring(str(bytearray(18)))
            else:
                RESULT.fromstring(data[start : start + SYMBOL_SIZE])

    # copying string section of symbol table
    RESULT.fromstring(data[pointer_to_symbol_table + SYMBOL_SIZE * number_of_symbols:])

    ofile = open(out_file, 'wb')
    RESULT.tofile(ofile)
    ofile.close()
