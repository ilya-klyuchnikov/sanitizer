# http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
# https://github.com/trailofbits/mcsema/tree/master/llvm-3.5/test/tools
import struct
import array

# https://github.com/anlongfei/llvm/blob/bd978bf7d464ca151bc7bc7d589ed3eccf7b8d5f/include/llvm/MC/MCSectionCOFF.h

# COFF File Header
SECTION_HEADERS_START = 20
# 4. Section Table (Section Headers)
SECTION_HEADER_SIZE = 40
# 5.2. COFF Relocations (Object Only)
RELOCATION_SIZE = 10
# see spec
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_LNK_COMDAT = 0x00001000
# https://docs.python.org/2/library/struct.html

SYMBOL_SYZE = 18


def strip(input_file, out_file):

    ifile = open(input_file, 'rb')
    bytes = ifile.read()
    ifile.close()

    n_sections, = struct.unpack_from('<h', bytes, 2)
    pointer_to_symbol_table, = struct.unpack_from('<I', bytes, 8)
    number_of_symbols, = struct.unpack_from('<I', bytes, 12)
    size_of_optional_header, = struct.unpack_from('<h', bytes, 16)

    assert size_of_optional_header == 0

    removed_sections = 0
    # an array of tuples - (start, size)
    removed_pieces = []

    # sorted_by_second = sorted(data, key=lambda tup: tup[1])

    removed_bytes = 0
    sections = []
    max_removed = 0
    # section mapping - old -> new (zero based)
    mapping = {}

    for section_i in range(0, n_sections):
        this_start = SECTION_HEADERS_START + section_i * SECTION_HEADER_SIZE
        sec_characteristics, = struct.unpack_from('<I', bytes, this_start + 36)
        to_strip = (sec_characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0) and (sec_characteristics & IMAGE_SCN_LNK_COMDAT == 0)

        if not to_strip:
            mapping[section_i] = section_i - removed_sections
        else:
            removed_sections += 1
            #removed_bytes += SECTION_HEADER_SIZE

    for section_i in range(0, n_sections):
        this_start = SECTION_HEADERS_START + section_i * SECTION_HEADER_SIZE
        name = bytes[this_start : this_start + 8]
        size_of_raw_data, = struct.unpack_from('<I', bytes, this_start + 16)
        ptr_to_raw_data, = struct.unpack_from('<I', bytes, this_start + 20)
        ptr_to_relocations, = struct.unpack_from('<I', bytes, this_start + 24)
        ptr_to_line_numbers, = struct.unpack_from('<I', bytes, this_start + 28)
        number_of_relocations, = struct.unpack_from('<h', bytes, this_start + 32)
        number_of_line_numbers, = struct.unpack_from('<h', bytes, this_start + 34)
        sec_characteristics, = struct.unpack_from('<I', bytes, this_start + 36)

        # is this enough?
        to_strip = (sec_characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0) and (sec_characteristics & IMAGE_SCN_LNK_COMDAT == 0)

        if ptr_to_relocations > 0:
            assert ptr_to_relocations >= max_removed

        if to_strip:
            if size_of_raw_data > 0:
                removed_pieces.append((ptr_to_raw_data, size_of_raw_data))
                max_removed = max(max_removed, ptr_to_raw_data + size_of_raw_data)

        if to_strip:
            removed_bytes = removed_bytes + size_of_raw_data #+ (number_of_relocations * RELOCATION_SIZE)
            sections.append((0, max(ptr_to_relocations - removed_bytes, 0)))
        else:
            sections.append((max(ptr_to_raw_data - removed_bytes, 0), max(ptr_to_relocations - removed_bytes, 0)))

    removed_symbols = 0
    aux_symbols = 0
    removing_symbol = False
    for i in range(0, number_of_symbols):
        start = pointer_to_symbol_table + SYMBOL_SYZE * i
        if aux_symbols == 0:
            aux_symbols, = struct.unpack_from('<B', bytes, start + 17)
            section, = struct.unpack_from('<h', bytes, start + 12)
            if section > 0:
                removing_symbol = (section - 1) not in mapping
                if removing_symbol:
                    removed_symbols += 1
        else:
            aux_symbols -= 1
            if removing_symbol:
                removed_symbols += 1

    RESULT = array.array('b')
    RESULT.fromstring(bytes[0:2])
    RESULT.fromstring(struct.pack('<h', n_sections))
    RESULT.fromstring(struct.pack('<I', 0))
    RESULT.fromstring(struct.pack('<I', pointer_to_symbol_table - removed_bytes))
    RESULT.fromstring(struct.pack('<I', number_of_symbols))
    RESULT.fromstring(bytes[16:20])

    for section_i in range(0, n_sections):
        section = sections[section_i]
        if section:
            this_start = SECTION_HEADERS_START + section_i * SECTION_HEADER_SIZE
            RESULT.fromstring(bytes[this_start : this_start + 16])
            ptr_to_raw_data, ptr_to_relocations = section
            if ptr_to_raw_data > 0:
                RESULT.fromstring(bytes[this_start + 16: this_start + 20])
            else:
                RESULT.fromstring(struct.pack('<I', 0))

            RESULT.fromstring(struct.pack('<I', ptr_to_raw_data))
            RESULT.fromstring(struct.pack('<I', ptr_to_relocations))
            RESULT.fromstring(bytes[this_start + 28 : this_start + 40])

    def stripped(i):
        for start, size in removed_pieces:
            if start <= i < start + size:
                return True
        return False

    for i in range(SECTION_HEADERS_START + n_sections*SECTION_HEADER_SIZE, pointer_to_symbol_table):
        if stripped(i):
            pass
        else:
            RESULT.fromstring(bytes[i])

    aux_symbols = 0
    removing_symbol = False
    # repacking symbol table now
    for i in range(0, number_of_symbols):
        start = pointer_to_symbol_table + SYMBOL_SYZE * i
        if aux_symbols == 0:
            aux_symbols, = struct.unpack_from('<B', bytes, start + 17)
            section, = struct.unpack_from('<h', bytes, start + 12)
            if section > 0:
                removing_symbol = (section - 1) not in mapping
                if removing_symbol:
                    new_section = 0
                else:
                    # coping with mapping
                    new_section = mapping[section - 1] + 1
                    # everything up to section
                new_section = section
                RESULT.fromstring(bytes[start : start + 12])
                RESULT.fromstring(struct.pack('<h', new_section))
                # everything after section
                RESULT.fromstring(bytes[start + 14 : start + SYMBOL_SYZE])
            else:
                removing_symbol = False
                RESULT.fromstring(bytes[start : start + SYMBOL_SYZE])
        else:
            aux_symbols -= 1
            if removing_symbol:
                print "PROCESSING AUX SYMBOL"
                RESULT.fromstring(str(bytearray(18)))
            else:
                RESULT.fromstring(bytes[start : start + SYMBOL_SYZE])


    # string section
    RESULT.fromstring(bytes[pointer_to_symbol_table + SYMBOL_SYZE * number_of_symbols:])

    ofile = open(out_file, 'wb')
    RESULT.tofile(ofile)
    ofile.close()
