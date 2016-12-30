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
OFFSET0 = 60
OFFSET1 = 8
SIZE = 4
DEFAULT_DATE_DLL = bytearray(4)


def fix_dll_timestamp(input_file, output_file):
    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    nexxxt, = struct.unpack_from(FORMAT, data, OFFSET0)
    print nexxxt
    tmp_start = nexxxt + OFFSET1

    output = data[:tmp_start] + DEFAULT_DATE_DLL + data[tmp_start + SIZE:]

    with open(output_file, 'wb') as ofile:
        ofile.write(output)
