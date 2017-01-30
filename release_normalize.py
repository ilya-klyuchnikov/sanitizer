import obj
import pefile
import lib

from optparse import OptionParser

parser = OptionParser()
parser.add_option("--input-object", dest="input_object",
                  help="input object file (implies --output-object)", metavar="FILE")
parser.add_option("--output-object", dest="output_object",
                  help="output object file", metavar="FILE")

parser.add_option("--input-image", dest="input_image",
                  help="input image file (exe or dll) (implies --output-image)", metavar="FILE")
parser.add_option("--output-image", dest="output_image",
                  help="output object file", metavar="FILE")

parser.add_option("--input-lib", dest="input_lib",
                  help="input lib file (implies --output-lib)", metavar="FILE")
parser.add_option("--output-lib", dest="output_lib",
                  help="output lib file", metavar="FILE")


def main(args=None):
    (options, args) = parser.parse_args(args)

    if options.input_object and options.output_object:
        print("stripping an object file")
        obj.strip(options.input_object, options.output_object)
    elif options.input_image and options.output_image:
        print("fixing an image")
        pe = pefile.PE(options.input_image)
        pe.default_timestamp()
        pe.write(options.output_image)
        pe.close()
    elif options.input_lib and options.output_lib:
        lib.fix_lib_timestamps(options.input_lib, options.output_lib)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
