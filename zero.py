import struct
import array
import optparse

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


def patch(input_file):
    """
    Strips a COFF file produced by a MSVC compiler, removing non-deterministic information.

    """
    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    output = array.array('b')

    header = FileHeader(data)
    header.time_date_stamp = 0


    header.write(output)
    output.fromstring(data[COFF_FILE_HEADER_SIZE:])

    with open(input_file, 'wb') as ofile:
        output.tofile(ofile)


def main(args=None):
    parser = optparse.OptionParser()
    parser.add_option("--input-object", dest="input_object",
                      help="input object file (implies --output-object)", metavar="FILE")

    (options, args) = parser.parse_args(args)

    if options.input_object:
        patch(options.input_object)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
