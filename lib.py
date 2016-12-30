import array

TIME_DATE_STAMP_OFFSET = 16
TIME_DATE_STAMP_LENGTH = 12

SIZE_OFFSET = 48
SIZE_LENGTH = 10

HEADER_SIZE = 60
HEADER_START = 8


def fix_timestamp(input_file, output_file):
    with open(input_file, 'rb') as ifile:
        data = ifile.read()

    signature = data[0:HEADER_START]
    assert signature == '!<arch>\n', signature

    header_start = HEADER_START

    output = array.array('b')
    output.fromstring(signature)

    while header_start < len(data):
        print '============='
        print 'start: {0} ({1})'.format(header_start, hex(header_start))

        time_date_stamp_str = data[header_start + TIME_DATE_STAMP_OFFSET : header_start + TIME_DATE_STAMP_OFFSET + TIME_DATE_STAMP_LENGTH]
        time_date_stamp = int(time_date_stamp_str)
        print 'date: {0} ({1})'.format(time_date_stamp, hex(time_date_stamp))

        size_str = data[header_start + SIZE_OFFSET : header_start + SIZE_OFFSET + SIZE_LENGTH]
        size = int(size_str)
        print 'size: {0}, ({1})'.format(size, hex(size))

        real_size = size + (size % 2)

        header_start = header_start + HEADER_SIZE + real_size


fix_timestamp('/Volumes/C/sanitizer110/tmp-lib/0/1/lib.lib', 'stripped.lib')