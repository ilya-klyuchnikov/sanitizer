import array
import struct

TIME_DATE_STAMP_OFFSET = 16
TIME_DATE_STAMP_LENGTH = 12

SIZE_OFFSET = 48
SIZE_LENGTH = 10

HEADER_SIZE = 60
HEADER_START = 8

DEFAULT_DATE_LIB = '0           '


def fix_lib_timestamps(input_file, output_file):
    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    signature = data[0:HEADER_START]
    assert signature == '!<arch>\n', signature

    header_start = HEADER_START

    output = array.array('b')
    output.fromstring(signature)

    while header_start < len(data):

        header = data[header_start:header_start + HEADER_SIZE]

        size_str = header[SIZE_OFFSET:SIZE_OFFSET + SIZE_LENGTH]
        size = int(size_str)
        real_size = size + (size % 2)

        stripped_header = header[:TIME_DATE_STAMP_OFFSET] + DEFAULT_DATE_LIB + header[TIME_DATE_STAMP_OFFSET + TIME_DATE_STAMP_LENGTH:]
        piece = data[header_start + HEADER_SIZE:header_start + HEADER_SIZE + real_size]
        output.fromstring(stripped_header)
        output.fromstring(piece)

        header_start = header_start + HEADER_SIZE + real_size

    with open(output_file, 'wb') as ofile:
        output.tofile(ofile)


FORMAT = '<I'
OFFSET_TO_NEW_HEADER = 60
SIGNATURE_SIZE = 4
IMAGE_NT_NUMBER_OF_SECTIONS_OFFSET = 2
IMAGE_NT_HEADERS_DATE_OFFSET = 4
SIZE = 4
DEFAULT_DATE_DLL = bytearray(4)

SIZE_OF_OPTIONAL_HEADER_OFFSET = 16
SIZE_OF_OPTIONAL_HEADER_FORMAT = '<h'



def fix_dll_timestamp(input_file, output_file):
    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    nt_header_start, = struct.unpack_from(FORMAT, data, OFFSET_TO_NEW_HEADER)
    print nt_header_start
    tmp_start = nt_header_start + SIGNATURE_SIZE + IMAGE_NT_HEADERS_DATE_OFFSET
    number_of_sections = struct.unpack_from(
        '<h',
        data,
        nt_header_start + SIGNATURE_SIZE + IMAGE_NT_NUMBER_OF_SECTIONS_OFFSET
    )

    size_of_optional_header = struct.unpack_from(
        SIZE_OF_OPTIONAL_HEADER_FORMAT,
        data,
        nt_header_start + SIGNATURE_SIZE + SIZE_OF_OPTIONAL_HEADER_OFFSET
    )


    output = data[:tmp_start] + DEFAULT_DATE_DLL + data[tmp_start + SIZE:]

    with open(output_file, 'wb') as ofile:
        ofile.write(output)
