import array

TIME_DATE_STAMP_OFFSET = 16
TIME_DATE_STAMP_LENGTH = 12

SIZE_OFFSET = 48
SIZE_LENGTH = 10

HEADER_SIZE = 60
HEADER_START = 8

DEFAULT_DATE = '0           '


def fix_timestamp(input_file, output_file):
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

        stripped_header = header[:TIME_DATE_STAMP_OFFSET] + DEFAULT_DATE + header[TIME_DATE_STAMP_OFFSET + TIME_DATE_STAMP_LENGTH:]
        piece = data[header_start + HEADER_SIZE:header_start + HEADER_SIZE + real_size]
        output.fromstring(stripped_header)
        output.fromstring(piece)

        header_start = header_start + HEADER_SIZE + real_size

    with open(output_file, 'wb') as ofile:
        output.tofile(ofile)
