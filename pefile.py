#!/usr/bin/python
# -*- coding: utf-8 -*-
"""pefile, Portable Executable reader module

All the PE file basic structures are available with their default names as
attributes of the instance returned.

Processed elements such as the import table are made available with lowercase
names, to differentiate them from the upper case basic structure names.

pefile has been tested against many edge cases such as corrupted and malformed
PEs as well as malware, which often attempts to abuse the format way beyond its
standard use. To the best of my knowledge most of the abuse is handled
gracefully.

Copyright (c) 2005-2016 Ero Carrera <ero.carrera@gmail.com>

All rights reserved.

For detailed copyright information see the file COPYING in the root of the
distribution archive.
"""

from __future__ import division
from __future__ import print_function

__author__ = 'Ero Carrera'
__version__ = '2016.3.28'
__contact__ = 'ero.carrera@gmail.com'

import struct
import sys
import time
import math
import string
import mmap
import ordlookup

from collections import Counter
from hashlib import sha1
from hashlib import sha256
from hashlib import sha512
from hashlib import md5

PY3 = sys.version_info > (3,)

def count_zeroes(data):
    try:
        # newbytes' count() takes a str in Python 2
        count = data.count('\0')
    except TypeError:
        # bytes' count() takes an int in Python 3
        count = data.count(0)
    return count

fast_load = False

# This will set a maximum length of a string to be retrieved from the file.
# It's there to prevent loading massive amounts of data from memory mapped
# files. Strings longer than 1MB should be rather rare.
MAX_STRING_LENGTH = 0x100000 # 2^20

# Limit maximum length for specific string types separately
MAX_IMPORT_NAME_LENGTH = 0x200
MAX_DLL_LENGTH = 0x200
MAX_SYMBOL_NAME_LENGTH = 0x200

IMAGE_DOS_SIGNATURE             = 0x5A4D
IMAGE_DOSZM_SIGNATURE           = 0x4D5A
IMAGE_NE_SIGNATURE              = 0x454E
IMAGE_LE_SIGNATURE              = 0x454C
IMAGE_LX_SIGNATURE              = 0x584C
IMAGE_TE_SIGNATURE              = 0x5A56 # Terse Executables have a 'VZ' signature

IMAGE_NT_SIGNATURE              = 0x00004550
IMAGE_NUMBEROF_DIRECTORY_ENTRIES= 16
IMAGE_ORDINAL_FLAG              = 0x80000000
IMAGE_ORDINAL_FLAG64            = 0x8000000000000000
OPTIONAL_HEADER_MAGIC_PE        = 0x10b
OPTIONAL_HEADER_MAGIC_PE_PLUS   = 0x20b


directory_entry_types = [
    ('IMAGE_DIRECTORY_ENTRY_EXPORT',        0),
    ('IMAGE_DIRECTORY_ENTRY_IMPORT',        1),
    ('IMAGE_DIRECTORY_ENTRY_RESOURCE',      2),
    ('IMAGE_DIRECTORY_ENTRY_EXCEPTION',     3),
    ('IMAGE_DIRECTORY_ENTRY_SECURITY',      4),
    ('IMAGE_DIRECTORY_ENTRY_BASERELOC',     5),
    ('IMAGE_DIRECTORY_ENTRY_DEBUG',         6),

    # Architecture on non-x86 platforms
    ('IMAGE_DIRECTORY_ENTRY_COPYRIGHT',     7),

    ('IMAGE_DIRECTORY_ENTRY_GLOBALPTR',     8),
    ('IMAGE_DIRECTORY_ENTRY_TLS',           9),
    ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG',   10),
    ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',  11),
    ('IMAGE_DIRECTORY_ENTRY_IAT',           12),
    ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',  13),
    ('IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',14),
    ('IMAGE_DIRECTORY_ENTRY_RESERVED',      15) ]

DIRECTORY_ENTRY = dict(
    [(e[1], e[0]) for e in directory_entry_types]+directory_entry_types)


section_characteristics = [
    ('IMAGE_SCN_TYPE_REG',                  0x00000000), # reserved
    ('IMAGE_SCN_TYPE_DSECT',                0x00000001), # reserved
    ('IMAGE_SCN_TYPE_NOLOAD',               0x00000002), # reserved
    ('IMAGE_SCN_TYPE_GROUP',                0x00000004), # reserved
    ('IMAGE_SCN_TYPE_NO_PAD',               0x00000008), # reserved
    ('IMAGE_SCN_TYPE_COPY',                 0x00000010), # reserved

    ('IMAGE_SCN_CNT_CODE',                  0x00000020),
    ('IMAGE_SCN_CNT_INITIALIZED_DATA',      0x00000040),
    ('IMAGE_SCN_CNT_UNINITIALIZED_DATA',    0x00000080),

    ('IMAGE_SCN_LNK_OTHER',                 0x00000100),
    ('IMAGE_SCN_LNK_INFO',                  0x00000200),
    ('IMAGE_SCN_LNK_OVER',                  0x00000400), # reserved
    ('IMAGE_SCN_LNK_REMOVE',                0x00000800),
    ('IMAGE_SCN_LNK_COMDAT',                0x00001000),

    ('IMAGE_SCN_MEM_PROTECTED',             0x00004000), # obsolete
    ('IMAGE_SCN_NO_DEFER_SPEC_EXC',         0x00004000),
    ('IMAGE_SCN_GPREL',                     0x00008000),
    ('IMAGE_SCN_MEM_FARDATA',               0x00008000),
    ('IMAGE_SCN_MEM_SYSHEAP',               0x00010000), # obsolete
    ('IMAGE_SCN_MEM_PURGEABLE',             0x00020000),
    ('IMAGE_SCN_MEM_16BIT',                 0x00020000),
    ('IMAGE_SCN_MEM_LOCKED',                0x00040000),
    ('IMAGE_SCN_MEM_PRELOAD',               0x00080000),

    ('IMAGE_SCN_ALIGN_1BYTES',              0x00100000),
    ('IMAGE_SCN_ALIGN_2BYTES',              0x00200000),
    ('IMAGE_SCN_ALIGN_4BYTES',              0x00300000),
    ('IMAGE_SCN_ALIGN_8BYTES',              0x00400000),
    ('IMAGE_SCN_ALIGN_16BYTES',             0x00500000), # default alignment
    ('IMAGE_SCN_ALIGN_32BYTES',             0x00600000),
    ('IMAGE_SCN_ALIGN_64BYTES',             0x00700000),
    ('IMAGE_SCN_ALIGN_128BYTES',            0x00800000),
    ('IMAGE_SCN_ALIGN_256BYTES',            0x00900000),
    ('IMAGE_SCN_ALIGN_512BYTES',            0x00A00000),
    ('IMAGE_SCN_ALIGN_1024BYTES',           0x00B00000),
    ('IMAGE_SCN_ALIGN_2048BYTES',           0x00C00000),
    ('IMAGE_SCN_ALIGN_4096BYTES',           0x00D00000),
    ('IMAGE_SCN_ALIGN_8192BYTES',           0x00E00000),
    ('IMAGE_SCN_ALIGN_MASK',                0x00F00000),

    ('IMAGE_SCN_LNK_NRELOC_OVFL',           0x01000000),
    ('IMAGE_SCN_MEM_DISCARDABLE',           0x02000000),
    ('IMAGE_SCN_MEM_NOT_CACHED',            0x04000000),
    ('IMAGE_SCN_MEM_NOT_PAGED',             0x08000000),
    ('IMAGE_SCN_MEM_SHARED',                0x10000000),
    ('IMAGE_SCN_MEM_EXECUTE',               0x20000000),
    ('IMAGE_SCN_MEM_READ',                  0x40000000),
    ('IMAGE_SCN_MEM_WRITE',                 0x80000000) ]

SECTION_CHARACTERISTICS = dict([(e[1], e[0]) for e in
    section_characteristics]+section_characteristics)


def power_of_two(val):
    return val != 0 and (val & (val-1)) == 0


# These come from the great article[1] which contains great insights on
# working with unicode in both Python 2 and 3.
# [1]: http://python3porting.com/problems.html
if not PY3:
    def handler(err):
        start = err.start
        end = err.end
        return (u"".join([u"\\x{0:02x}".format(ord(err.object[i])) for i in range(start,end)]),end)
    import codecs
    codecs.register_error('backslashreplace_', handler)
    def b(x):
        return x
else:
    import codecs
    codecs.register_error('backslashreplace_', codecs.lookup_error('backslashreplace'))
    def b(x):
        if isinstance(x, bytes):
            return x
        return codecs.encode(x, 'cp1252')


FILE_ALIGNEMNT_HARDCODED_VALUE = 0x200
FileAlignment_Warning = False # We only want to print the warning once
SectionAlignment_Warning = False # We only want to print the warning once



class UnicodeStringWrapperPostProcessor(object):
    """This class attempts to help the process of identifying strings
    that might be plain Unicode or Pascal. A list of strings will be
    wrapped on it with the hope the overlappings will help make the
    decision about their type."""

    def __init__(self, pe, rva_ptr):
        self.pe = pe
        self.rva_ptr = rva_ptr
        self.string = None

    def get_rva(self):
        """Get the RVA of the string."""
        return self.rva_ptr

    def __str__(self):
        """Return the escaped UTF-8 representation of the string."""
        return self.decode('utf-8', 'backslashreplace')

    def decode(self, *args):
        if not self.string:
            return ''
        return self.string.decode(*args)

    def invalidate(self):
        """Make this instance None, to express it's no known string type."""
        self = None

    def render_pascal_16(self):
        self.string = self.pe.get_string_u_at_rva(
            self.rva_ptr+2,
            max_length=self.get_pascal_16_length())

    def get_pascal_16_length(self):
        return self.__get_word_value_at_rva(self.rva_ptr)

    def __get_word_value_at_rva(self, rva):
        try:
            data = self.pe.get_data(self.rva_ptr, 2)
        except PEFormatError as e:
            return False

        if len(data)<2:
            return False

        return struct.unpack('<H', data)[0]

    def ask_unicode_16(self, next_rva_ptr):
        """The next RVA is taken to be the one immediately following this one.

        Such RVA could indicate the natural end of the string and will be checked
        to see if there's a Unicode NULL character there.
        """
        if self.__get_word_value_at_rva(next_rva_ptr-2) == 0:
            self.length = next_rva_ptr - self.rva_ptr
            return True

        return False

    def render_unicode_16(self):
        self.string = self.pe.get_string_u_at_rva(self.rva_ptr)


class PEFormatError(Exception):
    """Generic PE format error exception."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Dump(object):
    """Convenience class for dumping the PE information."""

    def __init__(self):
        self.text = list()

    def add_lines(self, txt, indent=0):
        """Adds a list of lines.

        The list can be indented with the optional argument 'indent'.
        """
        for line in txt:
            self.add_line(line, indent)

    def add_line(self, txt, indent=0):
        """Adds a line.

        The line can be indented with the optional argument 'indent'.
        """
        self.add(txt+'\n', indent)

    def add(self, txt, indent=0):
        """Adds some text, no newline will be appended.

        The text can be indented with the optional argument 'indent'.
        """
        self.text.append(u'{0}{1}'.format(' '*indent, txt))

    def add_header(self, txt):
        """Adds a header element."""
        self.add_line('{0}{1}{0}\n'.format('-'*10, txt))

    def add_newline(self):
        """Adds a newline."""
        self.text.append('\n')

    def get_text(self):
        """Get the text in its current state."""
        return u''.join(u'{0}'.format(b) for b in self.text)


STRUCT_SIZEOF_TYPES = {
    'x': 1, 'c': 1, 'b': 1, 'B': 1,
    'h': 2, 'H': 2,
    'i': 4, 'I': 4, 'l': 4, 'L': 4, 'f': 4,
    'q': 8, 'Q': 8, 'd': 8,
    's': 1 }

class Structure(object):
    """Prepare structure object to extract members from data.

    Format is a list containing definitions for the elements
    of the structure.
    """


    def __init__(self, format, name=None, file_offset=None):
        # Format is forced little endian, for big endian non Intel platforms
        self.__format__ = '<'
        self.__keys__ = []
        self.__format_length__ = 0
        self.__field_offsets__ = dict()
        self.__unpacked_data_elms__ = []
        self.__set_format__(format[1])
        self.__all_zeroes__ = False
        self.__file_offset__ = file_offset
        if name:
            self.name = name
        else:
            self.name = format[0]


    def __get_format__(self):
        return self.__format__

    def get_field_absolute_offset(self, field_name):
        """Return the offset within the field for the requested field in the structure."""
        return self.__file_offset__ + self.__field_offsets__[field_name]

    def get_field_relative_offset(self, field_name):
        """Return the offset within the structure for the requested field."""
        return self.__field_offsets__[field_name]

    def get_file_offset(self):
        return self.__file_offset__

    def set_file_offset(self, offset):
        self.__file_offset__ = offset

    def all_zeroes(self):
        """Returns true is the unpacked data is all zeros."""

        return self.__all_zeroes__

    def sizeof_type(self, t):
        count = 1
        _t = t
        if t[0] in string.digits:
            # extract the count
            count = int( ''.join([d for d in t if d in string.digits]) )
            _t = ''.join([d for d in t if d not in string.digits])
        return STRUCT_SIZEOF_TYPES[_t] * count

    def __set_format__(self, format):

        offset = 0
        for elm in format:
            if ',' in elm:
                elm_type, elm_name = elm.split(',', 1)
                self.__format__ += elm_type
                self.__unpacked_data_elms__.append(None)

                elm_names = elm_name.split(',')
                names = []
                for elm_name in elm_names:
                    if elm_name in self.__keys__:
                        search_list = [x[:len(elm_name)] for x in self.__keys__]
                        occ_count = search_list.count(elm_name)
                        elm_name =  '{0}_{1:d}'.format(elm_name, occ_count)
                    names.append(elm_name)
                    self.__field_offsets__[elm_name] = offset

                offset += self.sizeof_type(elm_type)

                # Some PE header structures have unions on them, so a certain
                # value might have different names, so each key has a list of
                # all the possible members referring to the data.
                self.__keys__.append(names)

        self.__format_length__ = struct.calcsize(self.__format__)


    def sizeof(self):
        """Return size of the structure."""

        return self.__format_length__


    def __unpack__(self, data):

        data = b(data)

        if len(data) > self.__format_length__:
            data = data[:self.__format_length__]

        # OC Patch:
        # Some malware have incorrect header lengths.
        # Fail gracefully if this occurs
        # Buggy malware: a29b0118af8b7408444df81701ad5a7f
        #
        elif len(data) < self.__format_length__:
            raise PEFormatError('Data length less than expected header length.')

        if count_zeroes(data) == len(data):
            self.__all_zeroes__ = True

        self.__unpacked_data_elms__ = struct.unpack(self.__format__, data)
        for i in range(len(self.__unpacked_data_elms__)):
            for key in self.__keys__[i]:
                setattr(self, key, self.__unpacked_data_elms__[i])


    def __pack__(self):

        new_values = []

        for i in range(len(self.__unpacked_data_elms__)):

            for key in self.__keys__[i]:
                new_val = getattr(self, key)
                old_val = self.__unpacked_data_elms__[i]

                # In the case of Unions, when the first changed value
                # is picked the loop is exited
                if new_val != old_val:
                    break

            new_values.append(new_val)

        return struct.pack(self.__format__, *new_values)


    def __str__(self):
        return '\n'.join( self.dump() )

    def __repr__(self):
        return '<Structure: %s>' % (' '.join( [' '.join(s.split()) for s in self.dump()] ))


    def dump(self, indentation=0):
        """Returns a string representation of the structure."""

        dump = []

        dump.append('[{0}]'.format(self.name))

        printable_bytes = [ord(i) for i in string.printable if i not in string.whitespace]

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, (int, long)):
                    val_str = '0x%-8X' % (val)
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        try:
                            val_str += ' [%s UTC]' % time.asctime(time.gmtime(val))
                        except exceptions.ValueError as e:
                            val_str += ' [INVALID TIME]'
                else:
                    val_str = bytearray(val)
                    val_str = ''.join(
                            [chr(i) if (i in printable_bytes) else
                             '\\x{0:02x}'.format(i) for i in val_str.rstrip(b'\x00')])

                dump.append('0x%-8X 0x%-3X %-30s %s' % (
                    self.__field_offsets__[key] + self.__file_offset__,
                    self.__field_offsets__[key], key+':', val_str))

        return dump


    def default_timestamp(self):
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, (int, long)):
                    if key == 'TimeDateStamp' or key == 'dwTimeStamp':
                        if getattr(self, key) != 0:
                            print(">>>>>>>>{0}".format(getattr(self, key)))
                            setattr(self, key, 0)



class SectionStructure(Structure):
    """Convenience section handling class."""

    def __init__(self, *argl, **argd):
        if 'pe' in argd:
            self.pe = argd['pe']
            del argd['pe']

        Structure.__init__(self, *argl, **argd)

    def get_data(self, start=None, length=None):
        """Get data chunk from a section.

        Allows to query data from the section by passing the
        addresses where the PE file would be loaded by default.
        It is then possible to retrieve code and data by its real
        addresses as it would be if loaded.

        Returns bytes() under Python 3.x and set() under 2.7
        """

        PointerToRawData_adj = self.pe.adjust_FileAlignment( self.PointerToRawData,
            self.pe.OPTIONAL_HEADER.FileAlignment )
        VirtualAddress_adj = self.pe.adjust_SectionAlignment( self.VirtualAddress,
            self.pe.OPTIONAL_HEADER.SectionAlignment, self.pe.OPTIONAL_HEADER.FileAlignment )

        if start is None:
            offset = PointerToRawData_adj
        else:
            offset = ( start - VirtualAddress_adj ) + PointerToRawData_adj

        if length is not None:
            end = offset + length
        else:
            end = offset + self.SizeOfRawData
        # PointerToRawData is not adjusted here as we might want to read any possible extra bytes
        # that might get cut off by aligning the start (and hence cutting something off the end)
        #
        if end > self.PointerToRawData + self.SizeOfRawData:
            end = self.PointerToRawData + self.SizeOfRawData
        return self.pe.__data__[offset:end]


    def __setattr__(self, name, val):

        if name == 'Characteristics':
            pass
        elif 'IMAGE_SCN_' in name and hasattr(self, name):
            if val:
                self.__dict__['Characteristics'] |= SECTION_CHARACTERISTICS[name]
            else:
                self.__dict__['Characteristics'] ^= SECTION_CHARACTERISTICS[name]

        self.__dict__[name] = val


    def get_rva_from_offset(self, offset):
        return offset - self.pe.adjust_FileAlignment( self.PointerToRawData,
            self.pe.OPTIONAL_HEADER.FileAlignment ) + self.pe.adjust_SectionAlignment( self.VirtualAddress,
            self.pe.OPTIONAL_HEADER.SectionAlignment, self.pe.OPTIONAL_HEADER.FileAlignment )


    def get_offset_from_rva(self, rva):
        return (rva -
            self.pe.adjust_SectionAlignment(
                self.VirtualAddress,
                self.pe.OPTIONAL_HEADER.SectionAlignment,
                self.pe.OPTIONAL_HEADER.FileAlignment )
            ) + self.pe.adjust_FileAlignment(
                self.PointerToRawData,
                self.pe.OPTIONAL_HEADER.FileAlignment )


    def contains_offset(self, offset):
        """Check whether the section contains the file offset provided."""

        if self.PointerToRawData is None:
           # bss and other sections containing only uninitialized data must have 0
           # and do not take space in the file
           return False
        return ( self.pe.adjust_FileAlignment( self.PointerToRawData,
                self.pe.OPTIONAL_HEADER.FileAlignment ) <=
                    offset <
                        self.pe.adjust_FileAlignment( self.PointerToRawData,
                            self.pe.OPTIONAL_HEADER.FileAlignment ) +
                                self.SizeOfRawData )


    def contains_rva(self, rva):
        """Check whether the section contains the address provided."""

        # Check if the SizeOfRawData is realistic. If it's bigger than the size of
        # the whole PE file minus the start address of the section it could be
        # either truncated or the SizeOfRawData contain a misleading value.
        # In either of those cases we take the VirtualSize
        #
        if len(self.pe.__data__) - self.pe.adjust_FileAlignment( self.PointerToRawData,
            self.pe.OPTIONAL_HEADER.FileAlignment ) < self.SizeOfRawData:
            # PECOFF documentation v8 says:
            # VirtualSize: The total size of the section when loaded into memory.
            # If this value is greater than SizeOfRawData, the section is zero-padded.
            # This field is valid only for executable images and should be set to zero
            # for object files.
            #
            size = self.Misc_VirtualSize
        else:
            size = max(self.SizeOfRawData, self.Misc_VirtualSize)

        VirtualAddress_adj = self.pe.adjust_SectionAlignment( self.VirtualAddress,
            self.pe.OPTIONAL_HEADER.SectionAlignment, self.pe.OPTIONAL_HEADER.FileAlignment )

        # Check whether there's any section after the current one that starts before the
        # calculated end for the current one, if so, cut the current section's size
        # to fit in the range up to where the next section starts.
        if (self.next_section_virtual_address is not None and
            self.next_section_virtual_address > self.VirtualAddress and
            VirtualAddress_adj + size > self.next_section_virtual_address):
                size = self.next_section_virtual_address - VirtualAddress_adj

        return VirtualAddress_adj <= rva < VirtualAddress_adj + size


    def contains(self, rva):
        #print "DEPRECATION WARNING: you should use contains_rva() instead of contains()"
        return self.contains_rva(rva)


    def get_entropy(self):
        """Calculate and return the entropy for the section."""

        return self.entropy_H( self.get_data() )


    def get_hash_sha1(self):
        """Get the SHA-1 hex-digest of the section's data."""

        if sha1 is not None:
            return sha1( self.get_data() ).hexdigest()


    def get_hash_sha256(self):
        """Get the SHA-256 hex-digest of the section's data."""

        if sha256 is not None:
            return sha256( self.get_data() ).hexdigest()


    def get_hash_sha512(self):
        """Get the SHA-512 hex-digest of the section's data."""

        if sha512 is not None:
            return sha512( self.get_data() ).hexdigest()


    def get_hash_md5(self):
        """Get the MD5 hex-digest of the section's data."""

        if md5 is not None:
            return md5( self.get_data() ).hexdigest()


    def entropy_H(self, data):
        """Calculate the entropy of a chunk of data."""

        if len(data) == 0:
            return 0.0

        occurences = Counter(bytearray(data))

        entropy = 0
        for x in occurences.values():
            p_x = float(x) / len(data)
            entropy -= p_x*math.log(p_x, 2)

        return entropy



class DataContainer(object):
    """Generic data container."""

    def __init__(self, **args):
        bare_setattr = super(DataContainer, self).__setattr__
        for key, value in list(args.items()):
            bare_setattr(key, value)



class ImportDescData(DataContainer):
    """Holds import descriptor information.

    dll:        name of the imported DLL
    imports:    list of imported symbols (ImportData instances)
    struct:     IMAGE_IMPORT_DESCRIPTOR structure
    """

class ImportData(DataContainer):
    """Holds imported symbol's information.

    ordinal:    Ordinal of the symbol
    name:       Name of the symbol
    bound:      If the symbol is bound, this contains
                the address.
    """

    def __setattr__(self, name, val):
        self.__dict__[name] = val


class ExportDirData(DataContainer):
    """Holds export directory information.

    struct:     IMAGE_EXPORT_DIRECTORY structure
    symbols:    list of exported symbols (ExportData instances)
"""

class ExportData(DataContainer):
    """Holds exported symbols' information.

    ordinal:    ordinal of the symbol
    address:    address of the symbol
    name:       name of the symbol (None if the symbol is
                exported by ordinal only)
    forwarder:  if the symbol is forwarded it will
                contain the name of the target symbol,
                None otherwise.
    """

    def __setattr__(self, name, val):
        self.__dict__[name] = val


class ResourceDirData(DataContainer):
    """Holds resource directory information.

    struct:     IMAGE_RESOURCE_DIRECTORY structure
    entries:    list of entries (ResourceDirEntryData instances)
    """

class ResourceDirEntryData(DataContainer):
    """Holds resource directory entry data.

    struct:     IMAGE_RESOURCE_DIRECTORY_ENTRY structure
    name:       If the resource is identified by name this
                attribute will contain the name string. None
                otherwise. If identified by id, the id is
                available at 'struct.Id'
    id:         the id, also in struct.Id
    directory:  If this entry has a lower level directory
                this attribute will point to the
                ResourceDirData instance representing it.
    data:       If this entry has no further lower directories
                and points to the actual resource data, this
                attribute will reference the corresponding
                ResourceDataEntryData instance.
    (Either of the 'directory' or 'data' attribute will exist,
    but not both.)
    """

class ResourceDataEntryData(DataContainer):
    """Holds resource data entry information.

    struct:     IMAGE_RESOURCE_DATA_ENTRY structure
    lang:       Primary language ID
    sublang:    Sublanguage ID
    """

class DebugData(DataContainer):
    """Holds debug information.

    struct:     IMAGE_DEBUG_DIRECTORY structure
    entries:    list of entries (IMAGE_DEBUG_TYPE instances)
    """

class BaseRelocationData(DataContainer):
    """Holds base relocation information.

    struct:     IMAGE_BASE_RELOCATION structure
    entries:    list of relocation data (RelocationData instances)
    """

class RelocationData(DataContainer):
    """Holds relocation information.

    type:       Type of relocation
                The type string is can be obtained by
                RELOCATION_TYPE[type]
    rva:        RVA of the relocation
    """
    def __setattr__(self, name, val):

        # If the instance doesn't yet have a struct attribute
        # it's not fully initialized so can't do any of the
        # following
        #
        if hasattr(self, 'struct'):
            # Get the word containing the type and data
            #
            word = self.struct.Data

            if name == 'type':
                word = (val << 12) | (word & 0xfff)
            elif name == 'rva':
                offset = val-self.base_rva
                if offset < 0:
                    offset = 0
                word = ( word & 0xf000) | ( offset & 0xfff)

            # Store the modified data
            #
            self.struct.Data = word

        self.__dict__[name] = val

class TlsData(DataContainer):
    """Holds TLS information.

    struct:     IMAGE_TLS_DIRECTORY structure
    """

class BoundImportDescData(DataContainer):
    """Holds bound import descriptor data.

    This directory entry will provide with information on the
    DLLs this PE files has been bound to (if bound at all).
    The structure will contain the name and timestamp of the
    DLL at the time of binding so that the loader can know
    whether it differs from the one currently present in the
    system and must, therefore, re-bind the PE's imports.

    struct:     IMAGE_BOUND_IMPORT_DESCRIPTOR structure
    name:       DLL name
    entries:    list of entries (BoundImportRefData instances)
                the entries will exist if this DLL has forwarded
                symbols. If so, the destination DLL will have an
                entry in this list.
    """

class LoadConfigData(DataContainer):
    """Holds Load Config data.

    struct:     IMAGE_LOAD_CONFIG_DIRECTORY structure
    name:       dll name
    """

class BoundImportRefData(DataContainer):
    """Holds bound import forwarder reference data.

    Contains the same information as the bound descriptor but
    for forwarded DLLs, if any.

    struct:     IMAGE_BOUND_FORWARDER_REF structure
    name:       dll name
    """


# Valid FAT32 8.3 short filename characters according to:
#  http://en.wikipedia.org/wiki/8.3_filename
# This will help decide whether DLL ASCII names are likely
# to be valid or otherwise corrupt data
#
# The filename length is not checked because the DLLs filename
# can be longer that the 8.3

if PY3:
    allowed_filename = b(
        string.ascii_lowercase + string.ascii_uppercase +
        string.digits + "!#$%&'()-@^_`{}~+,.;=[]")
else: # Python 2.x
    allowed_filename = b(
        string.lowercase + string.uppercase + string.digits +
        b"!#$%&'()-@^_`{}~+,.;=[]")

def is_valid_dos_filename(s):
    if s is None or not isinstance(s, (str, bytes)):
        return False
    # Allow path separators as import names can contain directories.
    allowed = allowed_filename + b'\\/'
    for c in set(s):
        if c not in allowed:
            return False
    return True


# Check if a imported name uses the valid accepted characters expected in mangled
# function names. If the symbol's characters don't fall within this charset
# we will assume the name is invalid
#
if PY3:
    allowed_function_name = b(
        string.ascii_lowercase + string.ascii_uppercase +
        string.digits + '_?@$()<>')
else:
    allowed_function_name = b(
        string.lowercase + string.uppercase +
        string.digits + b'_?@$()<>')

def is_valid_function_name(s):
    if s is None or not isinstance(s, (str, bytes)):
        return False
    for c in set(s):
        if c not in allowed_function_name:
            return False
    return True



class PE(object):
    """A Portable Executable representation.

    This class provides access to most of the information in a PE file.

    It expects to be supplied the name of the file to load or PE data
    to process and an optional argument 'fast_load' (False by default)
    which controls whether to load all the directories information,
    which can be quite time consuming.

    pe = pefile.PE('module.dll')
    pe = pefile.PE(name='module.dll')

    would load 'module.dll' and process it. If the data would be already
    available in a buffer the same could be achieved with:

    pe = pefile.PE(data=module_dll_data)

    The "fast_load" can be set to a default by setting its value in the
    module itself by means, for instance, of a "pefile.fast_load = True".
    That will make all the subsequent instances not to load the
    whole PE structure. The "full_load" method can be used to parse
    the missing data at a later stage.

    Basic headers information will be available in the attributes:

    DOS_HEADER
    NT_HEADERS
    FILE_HEADER
    OPTIONAL_HEADER

    All of them will contain among their attributes the members of the
    corresponding structures as defined in WINNT.H

    The raw data corresponding to the header (from the beginning of the
    file up to the start of the first section) will be available in the
    instance's attribute 'header' as a string.

    The sections will be available as a list in the 'sections' attribute.
    Each entry will contain as attributes all the structure's members.

    Directory entries will be available as attributes (if they exist):
    (no other entries are processed at this point)

    DIRECTORY_ENTRY_IMPORT (list of ImportDescData instances)
    DIRECTORY_ENTRY_EXPORT (ExportDirData instance)
    DIRECTORY_ENTRY_RESOURCE (ResourceDirData instance)
    DIRECTORY_ENTRY_DEBUG (list of DebugData instances)
    DIRECTORY_ENTRY_BASERELOC (list of BaseRelocationData instances)
    DIRECTORY_ENTRY_TLS
    DIRECTORY_ENTRY_BOUND_IMPORT (list of BoundImportData instances)

    The following dictionary attributes provide ways of mapping different
    constants. They will accept the numeric value and return the string
    representation and the opposite, feed in the string and get the
    numeric constant:

    DIRECTORY_ENTRY
    IMAGE_CHARACTERISTICS
    SECTION_CHARACTERISTICS
    DEBUG_TYPE
    SUBSYSTEM_TYPE
    MACHINE_TYPE
    RELOCATION_TYPE
    RESOURCE_TYPE
    LANG
    SUBLANG
    """

    #
    # Format specifications for PE structures.
    #

    __IMAGE_DOS_HEADER_format__ = ('IMAGE_DOS_HEADER',
        ('H,e_magic', 'H,e_cblp', 'H,e_cp',
        'H,e_crlc', 'H,e_cparhdr', 'H,e_minalloc',
        'H,e_maxalloc', 'H,e_ss', 'H,e_sp', 'H,e_csum',
        'H,e_ip', 'H,e_cs', 'H,e_lfarlc', 'H,e_ovno', '8s,e_res',
        'H,e_oemid', 'H,e_oeminfo', '20s,e_res2',
        'I,e_lfanew'))

    __IMAGE_FILE_HEADER_format__ = ('IMAGE_FILE_HEADER',
        ('H,Machine', 'H,NumberOfSections',
        'I,TimeDateStamp', 'I,PointerToSymbolTable',
        'I,NumberOfSymbols', 'H,SizeOfOptionalHeader',
        'H,Characteristics'))

    __IMAGE_DATA_DIRECTORY_format__ = ('IMAGE_DATA_DIRECTORY',
        ('I,VirtualAddress', 'I,Size'))


    __IMAGE_OPTIONAL_HEADER_format__ = ('IMAGE_OPTIONAL_HEADER',
        ('H,Magic', 'B,MajorLinkerVersion',
        'B,MinorLinkerVersion', 'I,SizeOfCode',
        'I,SizeOfInitializedData', 'I,SizeOfUninitializedData',
        'I,AddressOfEntryPoint', 'I,BaseOfCode', 'I,BaseOfData',
        'I,ImageBase', 'I,SectionAlignment', 'I,FileAlignment',
        'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion',
        'H,MajorImageVersion', 'H,MinorImageVersion',
        'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion',
        'I,Reserved1', 'I,SizeOfImage', 'I,SizeOfHeaders',
        'I,CheckSum', 'H,Subsystem', 'H,DllCharacteristics',
        'I,SizeOfStackReserve', 'I,SizeOfStackCommit',
        'I,SizeOfHeapReserve', 'I,SizeOfHeapCommit',
        'I,LoaderFlags', 'I,NumberOfRvaAndSizes' ))


    __IMAGE_OPTIONAL_HEADER64_format__ = ('IMAGE_OPTIONAL_HEADER64',
        ('H,Magic', 'B,MajorLinkerVersion',
        'B,MinorLinkerVersion', 'I,SizeOfCode',
        'I,SizeOfInitializedData', 'I,SizeOfUninitializedData',
        'I,AddressOfEntryPoint', 'I,BaseOfCode',
        'Q,ImageBase', 'I,SectionAlignment', 'I,FileAlignment',
        'H,MajorOperatingSystemVersion', 'H,MinorOperatingSystemVersion',
        'H,MajorImageVersion', 'H,MinorImageVersion',
        'H,MajorSubsystemVersion', 'H,MinorSubsystemVersion',
        'I,Reserved1', 'I,SizeOfImage', 'I,SizeOfHeaders',
        'I,CheckSum', 'H,Subsystem', 'H,DllCharacteristics',
        'Q,SizeOfStackReserve', 'Q,SizeOfStackCommit',
        'Q,SizeOfHeapReserve', 'Q,SizeOfHeapCommit',
        'I,LoaderFlags', 'I,NumberOfRvaAndSizes' ))


    __IMAGE_NT_HEADERS_format__ = ('IMAGE_NT_HEADERS', ('I,Signature',))

    __IMAGE_SECTION_HEADER_format__ = ('IMAGE_SECTION_HEADER',
        ('8s,Name', 'I,Misc,Misc_PhysicalAddress,Misc_VirtualSize',
        'I,VirtualAddress', 'I,SizeOfRawData', 'I,PointerToRawData',
        'I,PointerToRelocations', 'I,PointerToLinenumbers',
        'H,NumberOfRelocations', 'H,NumberOfLinenumbers',
        'I,Characteristics'))

    __IMAGE_DELAY_IMPORT_DESCRIPTOR_format__ = ('IMAGE_DELAY_IMPORT_DESCRIPTOR',
        ('I,grAttrs', 'I,szName', 'I,phmod', 'I,pIAT', 'I,pINT',
        'I,pBoundIAT', 'I,pUnloadIAT', 'I,dwTimeStamp'))

    __IMAGE_IMPORT_DESCRIPTOR_format__ =  ('IMAGE_IMPORT_DESCRIPTOR',
        ('I,OriginalFirstThunk,Characteristics',
        'I,TimeDateStamp', 'I,ForwarderChain', 'I,Name', 'I,FirstThunk'))

    __IMAGE_EXPORT_DIRECTORY_format__ =  ('IMAGE_EXPORT_DIRECTORY',
        ('I,Characteristics',
        'I,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion', 'I,Name',
        'I,Base', 'I,NumberOfFunctions', 'I,NumberOfNames',
        'I,AddressOfFunctions', 'I,AddressOfNames', 'I,AddressOfNameOrdinals'))

    __IMAGE_RESOURCE_DIRECTORY_format__ = ('IMAGE_RESOURCE_DIRECTORY',
        ('I,Characteristics',
        'I,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion',
        'H,NumberOfNamedEntries', 'H,NumberOfIdEntries'))

    __IMAGE_RESOURCE_DIRECTORY_ENTRY_format__ = ('IMAGE_RESOURCE_DIRECTORY_ENTRY',
        ('I,Name',
        'I,OffsetToData'))

    __IMAGE_RESOURCE_DATA_ENTRY_format__ = ('IMAGE_RESOURCE_DATA_ENTRY',
        ('I,OffsetToData', 'I,Size', 'I,CodePage', 'I,Reserved'))

    __VS_VERSIONINFO_format__ = ( 'VS_VERSIONINFO',
        ('H,Length', 'H,ValueLength', 'H,Type' ))

    __VS_FIXEDFILEINFO_format__ = ( 'VS_FIXEDFILEINFO',
        ('I,Signature', 'I,StrucVersion', 'I,FileVersionMS', 'I,FileVersionLS',
         'I,ProductVersionMS', 'I,ProductVersionLS', 'I,FileFlagsMask', 'I,FileFlags',
         'I,FileOS', 'I,FileType', 'I,FileSubtype', 'I,FileDateMS', 'I,FileDateLS'))

    __StringFileInfo_format__ = ( 'StringFileInfo',
        ('H,Length', 'H,ValueLength', 'H,Type' ))

    __StringTable_format__ = ( 'StringTable',
        ('H,Length', 'H,ValueLength', 'H,Type' ))

    __String_format__ = ( 'String',
        ('H,Length', 'H,ValueLength', 'H,Type' ))

    __Var_format__ = ( 'Var', ('H,Length', 'H,ValueLength', 'H,Type' ))

    __IMAGE_THUNK_DATA_format__ = ('IMAGE_THUNK_DATA',
        ('I,ForwarderString,Function,Ordinal,AddressOfData',))

    __IMAGE_THUNK_DATA64_format__ = ('IMAGE_THUNK_DATA',
        ('Q,ForwarderString,Function,Ordinal,AddressOfData',))

    __IMAGE_DEBUG_DIRECTORY_format__ = ('IMAGE_DEBUG_DIRECTORY',
        ('I,Characteristics', 'I,TimeDateStamp', 'H,MajorVersion',
        'H,MinorVersion', 'I,Type', 'I,SizeOfData', 'I,AddressOfRawData',
        'I,PointerToRawData'))

    __IMAGE_BASE_RELOCATION_format__ = ('IMAGE_BASE_RELOCATION',
        ('I,VirtualAddress', 'I,SizeOfBlock') )

    __IMAGE_BASE_RELOCATION_ENTRY_format__ = ('IMAGE_BASE_RELOCATION_ENTRY',
        ('H,Data',) )

    __IMAGE_TLS_DIRECTORY_format__ = ('IMAGE_TLS_DIRECTORY',
        ('I,StartAddressOfRawData', 'I,EndAddressOfRawData',
        'I,AddressOfIndex', 'I,AddressOfCallBacks',
        'I,SizeOfZeroFill', 'I,Characteristics' ) )

    __IMAGE_TLS_DIRECTORY64_format__ = ('IMAGE_TLS_DIRECTORY',
        ('Q,StartAddressOfRawData', 'Q,EndAddressOfRawData',
        'Q,AddressOfIndex', 'Q,AddressOfCallBacks',
        'I,SizeOfZeroFill', 'I,Characteristics' ) )

    __IMAGE_LOAD_CONFIG_DIRECTORY_format__ = ('IMAGE_LOAD_CONFIG_DIRECTORY',
        ('I,Size',
        'I,TimeDateStamp',
        'H,MajorVersion',
        'H,MinorVersion',
        'I,GlobalFlagsClear',
        'I,GlobalFlagsSet',
        'I,CriticalSectionDefaultTimeout',
        'I,DeCommitFreeBlockThreshold',
        'I,DeCommitTotalFreeThreshold',
        'I,LockPrefixTable',
        'I,MaximumAllocationSize',
        'I,VirtualMemoryThreshold',
        'I,ProcessHeapFlags',
        'I,ProcessAffinityMask',
        'H,CSDVersion',
        'H,Reserved1',
        'I,EditList',
        'I,SecurityCookie',
        'I,SEHandlerTable',
        'I,SEHandlerCount',
        'I,GuardCFCheckFunctionPointer',
        'I,Reserved2',
        'I,GuardCFFunctionTable',
        'I,GuardCFFunctionCount',
        'I,GuardFlags' ) )

    __IMAGE_LOAD_CONFIG_DIRECTORY64_format__ = ('IMAGE_LOAD_CONFIG_DIRECTORY',
        ('I,Size',
        'I,TimeDateStamp',
        'H,MajorVersion',
        'H,MinorVersion',
        'I,GlobalFlagsClear',
        'I,GlobalFlagsSet',
        'I,CriticalSectionDefaultTimeout',
        'Q,DeCommitFreeBlockThreshold',
        'Q,DeCommitTotalFreeThreshold',
        'Q,LockPrefixTable',
        'Q,MaximumAllocationSize',
        'Q,VirtualMemoryThreshold',
        'Q,ProcessAffinityMask',
        'I,ProcessHeapFlags',
        'H,CSDVersion',
        'H,Reserved1',
        'Q,EditList',
        'Q,SecurityCookie',
        'Q,SEHandlerTable',
        'Q,SEHandlerCount',
        'Q,GuardCFCheckFunctionPointer',
        'Q,Reserved2',
        'Q,GuardCFFunctionTable',
        'Q,GuardCFFunctionCount',
        'I,GuardFlags' ) )

    __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__ = ('IMAGE_BOUND_IMPORT_DESCRIPTOR',
        ('I,TimeDateStamp', 'H,OffsetModuleName', 'H,NumberOfModuleForwarderRefs'))

    __IMAGE_BOUND_FORWARDER_REF_format__ = ('IMAGE_BOUND_FORWARDER_REF',
        ('I,TimeDateStamp', 'H,OffsetModuleName', 'H,Reserved') )

    def __init__(self, name):

        self.sections = []

        self.__warnings = []

        self.PE_TYPE = None

        # This list will keep track of all the structures created.
        # That will allow for an easy iteration through the list
        # in order to save the modifications made
        self.__structures__ = []
        self.__from_file = None

        try:
            self.__parse__(name)
        except:
            self.close()
            raise


    def close(self):
        if ( self.__from_file is True and hasattr(self, '__data__') and
            ((isinstance(mmap.mmap, type) and isinstance(self.__data__, mmap.mmap)) or
           'mmap.mmap' in repr(type(self.__data__))) ):
                self.__data__.close()
                del self.__data__


    def __unpack_data__(self, format, data, file_offset):
        """Apply structure format to raw data.

        Returns and unpacked structure object if successful, None otherwise.
        """

        structure = Structure(format, file_offset=file_offset)

        try:
            structure.__unpack__(data)
        except PEFormatError as err:
            self.__warnings.append(
                'Corrupt header "{0}" at file offset {1}. Exception: {2}'.format(
                    format[0], file_offset, err) )
            return None

        self.__structures__.append(structure)

        return structure


    def __parse__(self, fname):
        """Parse a Portable Executable file.

        Loads a PE file, parsing all its structures and making them available
        through the instance's attributes.
        """
        fd = None
        try:
            fd = open(fname, 'rb')
            self.__data__ = fd.read()
            self.__from_file = True
        except IOError as excp:
            exception_msg = '{0}'.format(excp)
            if exception_msg:
                exception_msg = ': %s' % exception_msg
            raise Exception('Unable to access file \'{0}\'{1}'.format(fname, exception_msg))
        finally:
            if fd is not None:
                fd.close()

        dos_header_data = self.__data__[:64]
        if len(dos_header_data) != 64:
            raise PEFormatError('Unable to read the DOS Header, possibly a truncated file.')

        self.DOS_HEADER = self.__unpack_data__(
            self.__IMAGE_DOS_HEADER_format__,
            dos_header_data, file_offset=0)

        if self.DOS_HEADER.e_magic == IMAGE_DOSZM_SIGNATURE:
            raise PEFormatError('Probably a ZM Executable (not a PE file).')
        if not self.DOS_HEADER or self.DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE:
            raise PEFormatError('DOS Header magic not found.')

        # OC Patch:
        # Check for sane value in e_lfanew
        #
        if self.DOS_HEADER.e_lfanew > len(self.__data__):
            raise PEFormatError('Invalid e_lfanew value, probably not a PE file')

        nt_headers_offset = self.DOS_HEADER.e_lfanew

        self.NT_HEADERS = self.__unpack_data__(
            self.__IMAGE_NT_HEADERS_format__,
            self.__data__[nt_headers_offset:nt_headers_offset+4],
            file_offset = nt_headers_offset)

        if not self.NT_HEADERS or not self.NT_HEADERS.Signature:
            raise PEFormatError('NT Headers not found.')
        if self.NT_HEADERS.Signature != IMAGE_NT_SIGNATURE:
            raise PEFormatError('Invalid NT Headers signature.')

        self.FILE_HEADER = self.__unpack_data__(
            self.__IMAGE_FILE_HEADER_format__,
            self.__data__[nt_headers_offset+4:nt_headers_offset+4+32],
            file_offset = nt_headers_offset+4)

        if not self.FILE_HEADER:
            raise PEFormatError('File Header missing')

        optional_header_offset = nt_headers_offset+4+self.FILE_HEADER.sizeof()

        # Note: location of sections can be controlled from PE header:
        sections_offset = optional_header_offset + self.FILE_HEADER.SizeOfOptionalHeader

        self.OPTIONAL_HEADER = self.__unpack_data__(
            self.__IMAGE_OPTIONAL_HEADER_format__,
            # Read up to 256 bytes to allow creating a copy of too much data
            self.__data__[optional_header_offset:optional_header_offset+256],
            file_offset = optional_header_offset)

        # According to solardesigner's findings for his
        # Tiny PE project, the optional header does not
        # need fields beyond "Subsystem" in order to be
        # loadable by the Windows loader (given that zeros
        # are acceptable values and the header is loaded
        # in a zeroed memory page)
        # If trying to parse a full Optional Header fails
        # we try to parse it again with some 0 padding
        #
        MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 69

        if ( self.OPTIONAL_HEADER is None and
            len(self.__data__[optional_header_offset:optional_header_offset+0x200])
                >= MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE ):
            raise Exception("removed code")


        # Check the Magic in the OPTIONAL_HEADER and set the PE file
        # type accordingly
        #
        if self.OPTIONAL_HEADER is not None:

            if self.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:

                self.PE_TYPE = OPTIONAL_HEADER_MAGIC_PE

            elif self.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS:

                self.PE_TYPE = OPTIONAL_HEADER_MAGIC_PE_PLUS

                self.OPTIONAL_HEADER = self.__unpack_data__(
                    self.__IMAGE_OPTIONAL_HEADER64_format__,
                    self.__data__[optional_header_offset:optional_header_offset+0x200],
                    file_offset = optional_header_offset)

                # Again, as explained above, we try to parse
                # a reduced form of the Optional Header which
                # is still valid despite not including all
                # structure members
                #
                MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 69+4

                if ( self.OPTIONAL_HEADER is None and
                    len(self.__data__[optional_header_offset:optional_header_offset+0x200])
                        >= MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE ):
                    raise Exception("removed code")


        if not self.FILE_HEADER:
            raise PEFormatError('File Header missing')


        # OC Patch:
        # Die gracefully if there is no OPTIONAL_HEADER field
        # 975440f5ad5e2e4a92c4d9a5f22f75c1
        if self.OPTIONAL_HEADER is None:
            raise PEFormatError("No Optional Header found, invalid PE32 or PE32+ file.")

        self.OPTIONAL_HEADER.DATA_DIRECTORY = []
        offset = (optional_header_offset + self.OPTIONAL_HEADER.sizeof())


        self.NT_HEADERS.FILE_HEADER = self.FILE_HEADER
        self.NT_HEADERS.OPTIONAL_HEADER = self.OPTIONAL_HEADER

        MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES = 0x100
        # TODO ILYA - can it be simplified? - it can be simplified later
        for i in range(int(0x7fffffff & self.OPTIONAL_HEADER.NumberOfRvaAndSizes)):

            data = self.__data__[offset:offset+MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES]

            dir_entry = self.__unpack_data__(
                self.__IMAGE_DATA_DIRECTORY_format__,
                data,
                file_offset = offset)

            if dir_entry is None:
                break

            # Would fail if missing an entry
            # 1d4937b2fa4d84ad1bce0309857e70ca offending sample
            try:
                dir_entry.name = DIRECTORY_ENTRY[i]
            except (KeyError, AttributeError):
                break

            offset += dir_entry.sizeof()

            self.OPTIONAL_HEADER.DATA_DIRECTORY.append(dir_entry)

        offset = self.parse_sections(sections_offset)

        # OC Patch:
        # There could be a problem if there are no raw data sections
        # greater than 0
        # fc91013eb72529da005110a3403541b6 example
        # Should this throw an exception in the minimum header offset
        # can't be found?
        #
        rawDataPointers = [
            self.adjust_FileAlignment( s.PointerToRawData,
                self.OPTIONAL_HEADER.FileAlignment )
            for s in self.sections if s.PointerToRawData>0 ]

        if len(rawDataPointers) > 0:
            lowest_section_offset = min(rawDataPointers)
        else:
            lowest_section_offset = None

        if not lowest_section_offset or lowest_section_offset < offset:
            self.header = self.__data__[:offset]
        else:
            self.header = self.__data__[:lowest_section_offset]

        self.parse_data_directories()


    def default_timestamp(self):
        for structure in self.__structures__:
            structure.default_timestamp()

    def write(self, filename):
        """Write the PE file.

        This function will process all headers and components
        of the PE file and include all changes made (by just
        assigning to attributes in the PE objects) and write
        the changes back to a file whose name is provided as
        an argument. The filename is optional, if not
        provided the data will be returned as a 'str' object.
        """

        file_data = bytearray(self.__data__)

        for structure in self.__structures__:
            struct_data = bytearray(structure.__pack__())
            offset = structure.get_file_offset()
            file_data[offset:offset+len(struct_data)] = struct_data

        f = open(filename, 'wb+')
        f.write(file_data)
        f.close()
        return


    def parse_sections(self, offset):
        """Fetch the PE file sections.

        The sections will be readily available in the "sections" attribute.
        Its attributes will contain all the section information plus "data"
        a buffer containing the section's data.

        The "Characteristics" member will be processed and attributes
        representing the section characteristics (with the 'IMAGE_SCN_'
        string trimmed from the constant's names) will be added to the
        section instance.

        Refer to the SectionStructure class for additional info.
        """

        self.sections = []
        MAX_SIMULTANEOUS_ERRORS = 3
        for i in range(self.FILE_HEADER.NumberOfSections):
            simultaneous_errors = 0
            section = SectionStructure( self.__IMAGE_SECTION_HEADER_format__, pe=self )
            if not section:
                break
            section_offset = offset + section.sizeof() * i
            section.set_file_offset(section_offset)
            section_data = self.__data__[section_offset : section_offset + section.sizeof()]
            # Check if the section is all nulls and stop if so.
            if count_zeroes(section_data) == section.sizeof():
                self.__warnings.append(
                    'Invalid section {0}. Contents are null-bytes.'.format(i))
                break
            if len(section_data) == 0:
                self.__warnings.append(
                    'Invalid section {0}. No data in the file (is this corkami\'s virtsectblXP?).'.format(i))
                break
            section.__unpack__(section_data)
            self.__structures__.append(section)

            if section.SizeOfRawData+section.PointerToRawData > len(self.__data__):
                simultaneous_errors += 1
                self.__warnings.append(
                    'Error parsing section {0}. SizeOfRawData is larger than file.'.format(i))

            if self.adjust_FileAlignment( section.PointerToRawData,
                self.OPTIONAL_HEADER.FileAlignment ) > len(self.__data__):
                simultaneous_errors += 1
                self.__warnings.append(
                    'Error parsing section {0}. PointerToRawData points beyond the end of the file.'.format(i))

            if section.Misc_VirtualSize > 0x10000000:
                simultaneous_errors += 1
                self.__warnings.append(
                    'Suspicious value found parsing section {0}. VirtualSize is extremely large > 256MiB.'.format(i))

            if self.adjust_SectionAlignment( section.VirtualAddress,
                self.OPTIONAL_HEADER.SectionAlignment, self.OPTIONAL_HEADER.FileAlignment ) > 0x10000000:
                simultaneous_errors += 1
                self.__warnings.append(
                    'Suspicious value found parsing section {0}. VirtualAddress is beyond 0x10000000.'.format(i))

            if ( self.OPTIONAL_HEADER.FileAlignment != 0 and
                ( section.PointerToRawData % self.OPTIONAL_HEADER.FileAlignment) != 0):
                simultaneous_errors += 1
                self.__warnings.append(
                    ('Error parsing section {0}. '
                    'PointerToRawData should normally be '
                    'a multiple of FileAlignment, this might imply the file '
                    'is trying to confuse tools which parse this incorrectly.').format(i))

            if simultaneous_errors >= MAX_SIMULTANEOUS_ERRORS:
                self.__warnings.append('Too many warnings parsing section. Aborting.')
                break

            self.sections.append(section)

        # Sort the sections by their VirtualAddress and add a field to each of them
        # with the VirtualAddress of the next section. This will allow to check
        # for potentially overlapping sections in badly constructed PEs.
        self.sections.sort(key=lambda a: a.VirtualAddress)
        for idx, section in enumerate(self.sections):
            if idx == len(self.sections)-1:
                section.next_section_virtual_address = None
            else:
                section.next_section_virtual_address = self.sections[idx+1].VirtualAddress

        if self.FILE_HEADER.NumberOfSections > 0 and self.sections:
            return offset + self.sections[0].sizeof()*self.FILE_HEADER.NumberOfSections
        else:
            return offset



    def parse_data_directories(self):
        """Parse and process the PE file's data directories.

        If the optional argument 'directories' is given, only
        the directories at the specified indexes will be parsed.
        Such functionality allows parsing of areas of interest
        without the burden of having to parse all others.
        The directories can then be specified as:

        For export / import only:

          directories = [ 0, 1 ]

        or (more verbosely):

          directories = [ DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'] ]

        If 'directories' is a list, the ones that are processed will be removed,
        leaving only the ones that are not present in the image.

        If `forwarded_exports_only` is True, the IMAGE_DIRECTORY_ENTRY_EXPORT
        attribute will only contain exports that are forwarded to another DLL.

        If `import_dllnames_only` is True, symbols will not be parsed from
        the import table and the entries in the IMAGE_DIRECTORY_ENTRY_IMPORT
        attribute will not have a `symbols` attribute.
        """

        directory_parsing = (
            ('IMAGE_DIRECTORY_ENTRY_IMPORT', self.parse_import_directory),
            ('IMAGE_DIRECTORY_ENTRY_EXPORT', self.parse_export_directory),
            ('IMAGE_DIRECTORY_ENTRY_DEBUG', self.parse_debug_directory),
            #('IMAGE_DIRECTORY_ENTRY_BASERELOC', self.parse_relocations_directory),
            #('IMAGE_DIRECTORY_ENTRY_TLS', self.parse_directory_tls),
            ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG', self.parse_directory_load_config),
            ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT', self.parse_delay_import_directory),
            ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT', self.parse_directory_bound_imports) )

        for entry in directory_parsing:
            # OC Patch:
            #
            try:
                directory_index = DIRECTORY_ENTRY[entry[0]]
                dir_entry = self.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
            except IndexError:
                break

            if dir_entry.VirtualAddress:
                value = entry[1](dir_entry.VirtualAddress, dir_entry.Size)
                if value:
                    setattr(self, entry[0][6:], value)



    def parse_directory_bound_imports(self, rva, size):
        """"""

        bnd_descr = Structure(self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__)
        bnd_descr_size = bnd_descr.sizeof()
        start = rva

        bound_imports = []
        while True:
            bnd_descr = self.__unpack_data__(
                self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__,
                   self.__data__[rva:rva+bnd_descr_size],
                   file_offset = rva)
            if bnd_descr is None:
                # If can't parse directory then silently return.
                # This directory does not necessarily have to be valid to
                # still have a valid PE file

                self.__warnings.append(
                    'The Bound Imports directory exists but can\'t be parsed.')

                return

            if bnd_descr.all_zeroes():
                break

            rva += bnd_descr.sizeof()

            section = self.get_section_by_offset(rva)
            file_offset = self.get_offset_from_rva(rva)
            if section is None:
                safety_boundary = len(self.__data__) - file_offset
                sections_after_offset = [
                    s.PointerToRawData for s in self.sections
                    if s.PointerToRawData > file_offset]
                if sections_after_offset:
                    # Find the first section starting at a later offset than that
                    # specified by 'rva'
                    first_section_after_offset = min(sections_after_offset)
                    section = self.get_section_by_offset(first_section_after_offset)
                    if section is not None:
                        safety_boundary = section.PointerToRawData - file_offset
            else:
                safety_boundary = (section.PointerToRawData +
                                   len(section.get_data()) - file_offset)
            if not section:
                self.__warnings.append(
                    ('RVA of IMAGE_BOUND_IMPORT_DESCRIPTOR points '
                     'to an invalid address: {0:x}').format(rva))
                return


            forwarder_refs = []
            # 8 is the size of __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__
            for idx in range(min(bnd_descr.NumberOfModuleForwarderRefs,
                                 int(safety_boundary / 8))):
                # Both structures IMAGE_BOUND_IMPORT_DESCRIPTOR and
                # IMAGE_BOUND_FORWARDER_REF have the same size.
                bnd_frwd_ref = self.__unpack_data__(
                    self.__IMAGE_BOUND_FORWARDER_REF_format__,
                    self.__data__[rva:rva+bnd_descr_size],
                    file_offset = rva)
                # OC Patch:
                if not bnd_frwd_ref:
                    raise PEFormatError(
                        "IMAGE_BOUND_FORWARDER_REF cannot be read")
                rva += bnd_frwd_ref.sizeof()

                offset = start+bnd_frwd_ref.OffsetModuleName
                name_str =  self.get_string_from_data(
                    0, self.__data__[offset : offset + MAX_STRING_LENGTH])

                # OffsetModuleName points to a DLL name. These shouldn't be too long.
                # Anything longer than a safety length of 128 will be taken to indicate
                # a corrupt entry and abort the processing of these entries.
                # Names shorted than 4 characters will be taken as invalid as well.

                if name_str:
                    invalid_chars = [
                        c for c in bytearray(name_str) if
                            chr(c) not in string.printable]
                    if len(name_str) > 256 or invalid_chars:
                        break

                forwarder_refs.append(BoundImportRefData(
                    struct = bnd_frwd_ref,
                    name = name_str))

            offset = start+bnd_descr.OffsetModuleName
            name_str = self.get_string_from_data(
                0, self.__data__[offset : offset + MAX_STRING_LENGTH])

            if name_str:
                invalid_chars = [
                    c for c in bytearray(name_str) if
                        chr(c) not in string.printable]
                if len(name_str) > 256 or invalid_chars:
                    break

            if not name_str:
                break
            bound_imports.append(
                BoundImportDescData(
                    struct = bnd_descr,
                    name = name_str,
                    entries = forwarder_refs))

        return bound_imports


    def parse_directory_tls(self, rva, size):
        """"""

        # By default let's pretend the format is a 32-bit PE. It may help
        # produce some output for files where the Magic in the Optional Header
        # is incorrect.
        format = self.__IMAGE_TLS_DIRECTORY_format__

        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            format = self.__IMAGE_TLS_DIRECTORY64_format__

        try:
            tls_struct = self.__unpack_data__(
                format,
                self.get_data( rva, Structure(format).sizeof() ),
                file_offset = self.get_offset_from_rva(rva))
        except PEFormatError:
            self.__warnings.append(
                'Invalid TLS information. Can\'t read '
                'data at RVA: 0x%x' % rva)
            tls_struct = None

        if not tls_struct:
            return None

        return TlsData( struct = tls_struct )


    def parse_directory_load_config(self, rva, size):
        """"""

        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            format = self.__IMAGE_LOAD_CONFIG_DIRECTORY_format__

        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            format = self.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__

        try:
            load_config_struct = self.__unpack_data__(
                format,
                self.get_data( rva, Structure(format).sizeof() ),
                file_offset = self.get_offset_from_rva(rva))
        except PEFormatError:
            self.__warnings.append(
                'Invalid LOAD_CONFIG information. Can\'t read '
                'data at RVA: 0x%x' % rva)
            load_config_struct = None

        if not load_config_struct:
            return None

        return LoadConfigData( struct = load_config_struct )


    def parse_relocations_directory(self, rva, size):
        """"""

        rlc_size = Structure(self.__IMAGE_BASE_RELOCATION_format__).sizeof()
        end = rva+size

        relocations = []
        while rva < end:

            # OC Patch:
            # Malware that has bad RVA entries will cause an error.
            # Just continue on after an exception
            #
            try:
                rlc = self.__unpack_data__(
                    self.__IMAGE_BASE_RELOCATION_format__,
                    self.get_data(rva, rlc_size),
                    file_offset = self.get_offset_from_rva(rva) )
            except PEFormatError:
                self.__warnings.append(
                    'Invalid relocation information. Can\'t read '
                    'data at RVA: 0x%x' % rva)
                rlc = None

            if not rlc:
                break

            # rlc.VirtualAddress must lie within the Image
            if rlc.VirtualAddress > self.OPTIONAL_HEADER.SizeOfImage:
                self.__warnings.append(
                    'Invalid relocation information. VirtualAddress outside'
                    ' of Image: 0x%x' % rlc.VirtualAddress)
                break

            # rlc.SizeOfBlock must be less or equal than the size of the image
            # (It's a rather loose sanity test)
            if rlc.SizeOfBlock > self.OPTIONAL_HEADER.SizeOfImage:
                self.__warnings.append(
                    'Invalid relocation information. SizeOfBlock too large'
                    ': %d' % rlc.SizeOfBlock)
                break

            reloc_entries = self.parse_relocations(
                rva+rlc_size, rlc.VirtualAddress, rlc.SizeOfBlock-rlc_size )

            relocations.append(
                BaseRelocationData(
                    struct = rlc,
                    entries = reloc_entries))

            if not rlc.SizeOfBlock:
                break
            rva += rlc.SizeOfBlock

        return relocations


    def parse_relocations(self, data_rva, rva, size):
        """"""

        try:
            data = self.get_data(data_rva, size)
            file_offset = self.get_offset_from_rva(data_rva)
        except PEFormatError as excp:
            self.__warnings.append(
                'Bad RVA in relocation data: 0x%x' % (data_rva))
            return []

        entries = []
        offsets_and_type = []
        for idx in range( int(len(data) / 2) ):

            entry = self.__unpack_data__(
                self.__IMAGE_BASE_RELOCATION_ENTRY_format__,
                data[idx*2:(idx+1)*2],
                file_offset = file_offset )

            if not entry:
                break
            word = entry.Data

            reloc_type = (word>>12)
            reloc_offset = (word & 0x0fff)
            if (reloc_offset, reloc_type) in offsets_and_type:
                self.__warnings.append(
                    'Overlapping offsets in relocation data '
                    'data at RVA: 0x%x' % (reloc_offset+rva))
                break
            if len(offsets_and_type) >= 1000:
                offsets_and_type.pop()
            offsets_and_type.insert(0, (reloc_offset, reloc_type))

            entries.append(
                RelocationData(
                    struct = entry,
                    type = reloc_type,
                    base_rva = rva,
                    rva = reloc_offset+rva))
            file_offset += entry.sizeof()

        return entries


    def parse_debug_directory(self, rva, size):
        """"""

        dbg_size = Structure(self.__IMAGE_DEBUG_DIRECTORY_format__).sizeof()

        debug = []
        for idx in range(int(size / dbg_size)):
            try:
                data = self.get_data(rva+dbg_size*idx, dbg_size)
            except PEFormatError as e:
                self.__warnings.append(
                    'Invalid debug information. Can\'t read '
                    'data at RVA: 0x%x' % rva)
                return None

            dbg = self.__unpack_data__(
                self.__IMAGE_DEBUG_DIRECTORY_format__,
                data, file_offset = self.get_offset_from_rva(rva+dbg_size*idx))

            if not dbg:
                return None

            # apply structure according to DEBUG_TYPE
            # http://www.debuginfo.com/articles/debuginfomatch.html
            #
            dbg_type = None

            if dbg.Type == 1:
            # IMAGE_DEBUG_TYPE_COFF
                pass

            elif dbg.Type == 2:
                # if IMAGE_DEBUG_TYPE_CODEVIEW
                dbg_type_offset = dbg.PointerToRawData
                dbg_type_size = dbg.SizeOfData
                dbg_type_data = self.__data__[dbg_type_offset:dbg_type_offset+dbg_type_size]

                if dbg_type_data[:4] == b'RSDS':
                    # pdb7.0
                    __CV_INFO_PDB70_format__ = ['CV_INFO_PDB70',
                        ['I,CvSignature',
                         'I,Signature_Data1', # Signature is of GUID type
                         'H,Signature_Data2',
                         'H,Signature_Data3',
                         'H,Signature_Data4',
                         'H,Signature_Data5',
                         'I,Signature_Data6',
                         'I,Age']]
                    pdbFileName_size = (
                        dbg_type_size -
                        Structure(__CV_INFO_PDB70_format__).sizeof())

                    # pdbFileName_size can be negative here, as seen in the malware sample with hash
                    # MD5:    7c297600870d026c014d42596bb9b5fd
                    # SHA256: 83f4e63681fcba8a9d7bbb1688c71981b1837446514a1773597e0192bba9fac3
                    # Checking for positive size here to ensure proper parsing.
                    if pdbFileName_size > 0:
                        __CV_INFO_PDB70_format__[1].append(
                            '{0}s,PdbFileName'.format(pdbFileName_size))
                    dbg_type = self.__unpack_data__(
                        __CV_INFO_PDB70_format__,
                        dbg_type_data,
                        dbg_type_offset)

                elif dbg_type_data[:4] == b'NB10':
                    # pdb2.0
                    __CV_INFO_PDB20_format__ = ['CV_INFO_PDB20',
                        ['I,CvHeaderSignature',
                         'I,CvHeaderOffset',
                         'I,Signature',
                         'I,Age']]
                    pdbFileName_size = (
                        dbg_type_size -
                        Structure(__CV_INFO_PDB20_format__).sizeof())

                    # As with the PDB 7.0 case, ensuring a positive size for pdbFileName_size
                    # to ensure proper parsing.
                    if pdbFileName_size > 0:
                        # Add the last variable-length string field.
                        __CV_INFO_PDB20_format__[1].append(
                            '{0}s,PdbFileName'.format(pdbFileName_size))
                    dbg_type = self.__unpack_data__(
                        __CV_INFO_PDB20_format__,
                        dbg_type_data,
                        dbg_type_offset)

            elif dbg.Type == 4:
                # IMAGE_DEBUG_TYPE_MISC
                dbg_type_offset = dbg.PointerToRawData
                dbg_type_size = dbg.SizeOfData
                dbg_type_data = self.__data__[dbg_type_offset:dbg_type_offset+dbg_type_size]
                ___IMAGE_DEBUG_MISC_format__ = ['IMAGE_DEBUG_MISC',
                    ['I,DataType',
                     'I,Length',
                     'B,Unicode',
                     'B,Reserved1',
                     'H,Reserved2']]
                dbg_type_partial = self.__unpack_data__(
                        ___IMAGE_DEBUG_MISC_format__,
                        dbg_type_data,
                        dbg_type_offset)

                # Need to check that dbg_type_partial contains a correctly unpacked data
                # structure, as the malware sample with the following hash
                # MD5:    5e7d6707d693108de5a303045c17d95b
                # SHA256: 5dd94a95025f3b6e3dd440d52f7c6d2964fdd1aa119e0ee92e38c7bf83829e5c
                # contains a value of None for dbg_type_partial after unpacking, presumably
                # due to a malformed DEBUG entry.
                if dbg_type_partial:
                    # The Unicode bool should be set to 0 or 1.
                    if dbg_type_partial.Unicode in (0, 1):
                        data_size = (
                            dbg_type_size -
                            Structure(___IMAGE_DEBUG_MISC_format__).sizeof())

                        # As with the PDB case, ensuring a positive size for data_size here
                        # to ensure proper parsing.
                        if data_size > 0:
                            ___IMAGE_DEBUG_MISC_format__[1].append(
                                    '{0}s,Data'.format(data_size))
                        dbg_type = self.__unpack_data__(
                                ___IMAGE_DEBUG_MISC_format__,
                                dbg_type_data,
                                dbg_type_offset)

            debug.append(
                DebugData(
                    struct = dbg,
                    entry = dbg_type))

        return debug


    def parse_resource_data_entry(self, rva):
        """Parse a data entry from the resources directory."""

        try:
            # If the RVA is invalid all would blow up. Some EXEs seem to be
            # specially nasty and have an invalid RVA.
            data = self.get_data(rva, Structure(self.__IMAGE_RESOURCE_DATA_ENTRY_format__).sizeof() )
        except PEFormatError as excp:
            self.__warnings.append(
                'Error parsing a resource directory data entry, '
                'the RVA is invalid: 0x%x' % ( rva ) )
            return None

        data_entry = self.__unpack_data__(
            self.__IMAGE_RESOURCE_DATA_ENTRY_format__, data,
            file_offset = self.get_offset_from_rva(rva) )

        return data_entry


    def parse_resource_entry(self, rva):
        """Parse a directory entry from the resources directory."""

        try:
            data = self.get_data( rva, Structure(self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__).sizeof() )
        except PEFormatError as excp:
            # A warning will be added by the caller if this method returns None
            return None

        resource = self.__unpack_data__(
            self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__, data,
            file_offset = self.get_offset_from_rva(rva) )

        if resource is None:
            return None

        #resource.NameIsString = (resource.Name & 0x80000000L) >> 31
        resource.NameOffset = resource.Name & 0x7FFFFFFF

        resource.__pad = resource.Name & 0xFFFF0000
        resource.Id = resource.Name & 0x0000FFFF

        resource.DataIsDirectory = (resource.OffsetToData & 0x80000000) >> 31
        resource.OffsetToDirectory = resource.OffsetToData & 0x7FFFFFFF

        return resource


    def parse_version_information(self, version_struct):
        """Parse version information structure.

        The date will be made available in three attributes of the PE object.

        VS_VERSIONINFO     will contain the first three fields of the main structure:
            'Length', 'ValueLength', and 'Type'

        VS_FIXEDFILEINFO    will hold the rest of the fields, accessible as sub-attributes:
            'Signature', 'StrucVersion', 'FileVersionMS', 'FileVersionLS',
            'ProductVersionMS', 'ProductVersionLS', 'FileFlagsMask', 'FileFlags',
            'FileOS', 'FileType', 'FileSubtype', 'FileDateMS', 'FileDateLS'

        FileInfo    is a list of all StringFileInfo and VarFileInfo structures.

        StringFileInfo structures will have a list as an attribute named 'StringTable'
        containing all the StringTable structures. Each of those structures contains a
        dictionary 'entries' with all the key / value version information string pairs.

        VarFileInfo structures will have a list as an attribute named 'Var' containing
        all Var structures. Each Var structure will have a dictionary as an attribute
        named 'entry' which will contain the name and value of the Var.
        """


        # Retrieve the data for the version info resource
        #
        start_offset = self.get_offset_from_rva( version_struct.OffsetToData )
        raw_data = self.__data__[ start_offset : start_offset+version_struct.Size ]


        # Map the main structure and the subsequent string
        #
        versioninfo_struct = self.__unpack_data__(
            self.__VS_VERSIONINFO_format__, raw_data,
            file_offset = start_offset )

        if versioninfo_struct is None:
            return

        ustr_offset = version_struct.OffsetToData + versioninfo_struct.sizeof()
        section = self.get_section_by_rva(ustr_offset)
        section_end = None
        if section:
            section_end = section.VirtualAddress + max(
                section.SizeOfRawData, section.Misc_VirtualSize)

        versioninfo_string = None
        # These should return 'ascii' decoded data. For the case when it's
        # garbled data the ascii string will retain the byte values while
        # encoding it to something else may yield values that don't match the
        # file's contents.
        try:
            if section_end is None:
                versioninfo_string = self.get_string_u_at_rva(
                    ustr_offset, encoding='ascii')
            else:
                versioninfo_string = self.get_string_u_at_rva(
                    ustr_offset, (section_end - ustr_offset) >> 1,
                    encoding='ascii')
        except PEFormatError as excp:
            self.__warnings.append(
                'Error parsing the version information, '
                'attempting to read VS_VERSION_INFO string. Can\'t '
                'read unicode string at offset 0x%x' % (
                ustr_offset))


        # If the structure does not contain the expected name, it's assumed to
        # be invalid
        if (versioninfo_string is not None and
            versioninfo_string != b'VS_VERSION_INFO'):
            if len(versioninfo_string) > 128:
                excerpt = versioninfo_string[:128].decode('ascii')
                # Don't leave any half-escaped characters
                excerpt = excerpt[:excerpt.rfind('\\u')]
                versioninfo_string = \
                    b('{0} ... ({1} bytes, too long to display)'.format(
                        excerpt,
                        len(versioninfo_string)))
            self.__warnings.append('Invalid VS_VERSION_INFO block: {0}'.format(
                versioninfo_string.decode('ascii').replace('\00', '\\00')))
            return

        # Set the PE object's VS_VERSIONINFO to this one
        self.VS_VERSIONINFO = versioninfo_struct

        # The the Key attribute to point to the unicode string identifying the structure
        self.VS_VERSIONINFO.Key = versioninfo_string

        if versioninfo_string is None:
            versioninfo_string = ''
        # Process the fixed version information, get the offset and structure
        fixedfileinfo_offset = self.dword_align(
            versioninfo_struct.sizeof() + 2 * (len(versioninfo_string) + 1),
            version_struct.OffsetToData)
        fixedfileinfo_struct = self.__unpack_data__(
            self.__VS_FIXEDFILEINFO_format__,
            raw_data[fixedfileinfo_offset:],
            file_offset = start_offset+fixedfileinfo_offset )

        if not fixedfileinfo_struct:
            return

        # Set the PE object's VS_FIXEDFILEINFO to this one
        self.VS_FIXEDFILEINFO = fixedfileinfo_struct

        # Start parsing all the StringFileInfo and VarFileInfo structures

        # Get the first one
        stringfileinfo_offset = self.dword_align(
            fixedfileinfo_offset + fixedfileinfo_struct.sizeof(),
            version_struct.OffsetToData)
        original_stringfileinfo_offset = stringfileinfo_offset

        # Set the PE object's attribute that will contain them all.
        self.FileInfo = list()

        while True:

            # Process the StringFileInfo/VarFileInfo structure
            stringfileinfo_struct = self.__unpack_data__(
                self.__StringFileInfo_format__,
                raw_data[stringfileinfo_offset:],
                file_offset = start_offset+stringfileinfo_offset )

            if stringfileinfo_struct is None:
                self.__warnings.append(
                    'Error parsing StringFileInfo/VarFileInfo struct' )
                return None

            # Get the subsequent string defining the structure.
            ustr_offset = ( version_struct.OffsetToData +
                stringfileinfo_offset + versioninfo_struct.sizeof() )
            try:
                stringfileinfo_string = self.get_string_u_at_rva( ustr_offset )
            except PEFormatError as excp:
                self.__warnings.append(
                    'Error parsing the version information, '
                    'attempting to read StringFileInfo string. Can\'t '
                    'read unicode string at offset 0x{0:x}'.format(ustr_offset))
                break

            # Set such string as the Key attribute
            stringfileinfo_struct.Key = stringfileinfo_string


            # Append the structure to the PE object's list
            self.FileInfo.append(stringfileinfo_struct)


            # Parse a StringFileInfo entry
            if stringfileinfo_string and stringfileinfo_string.startswith(b'StringFileInfo'):

                if stringfileinfo_struct.Type in (0,1) and stringfileinfo_struct.ValueLength == 0:

                    stringtable_offset = self.dword_align(
                        stringfileinfo_offset + stringfileinfo_struct.sizeof() +
                            2*(len(stringfileinfo_string)+1),
                        version_struct.OffsetToData)

                    stringfileinfo_struct.StringTable = list()

                    # Process the String Table entries
                    while True:

                        stringtable_struct = self.__unpack_data__(
                            self.__StringTable_format__,
                            raw_data[stringtable_offset:],
                            file_offset = start_offset+stringtable_offset )

                        if not stringtable_struct:
                            break

                        ustr_offset = ( version_struct.OffsetToData + stringtable_offset +
                            stringtable_struct.sizeof() )
                        try:
                            stringtable_string = self.get_string_u_at_rva(ustr_offset)
                        except PEFormatError as excp:
                            self.__warnings.append(
                                'Error parsing the version information, '
                                'attempting to read StringTable string. Can\'t '
                                'read unicode string at offset 0x{0:x}'.format(ustr_offset) )
                            break

                        stringtable_struct.LangID = stringtable_string
                        stringtable_struct.entries = dict()
                        stringtable_struct.entries_offsets = dict()
                        stringtable_struct.entries_lengths = dict()
                        stringfileinfo_struct.StringTable.append(stringtable_struct)

                        entry_offset = self.dword_align(
                            stringtable_offset + stringtable_struct.sizeof() +
                                2*(len(stringtable_string)+1),
                            version_struct.OffsetToData)

                        # Process all entries in the string table

                        while entry_offset < stringtable_offset + stringtable_struct.Length:

                            string_struct = self.__unpack_data__(
                                self.__String_format__, raw_data[entry_offset:],
                                file_offset = start_offset+entry_offset )

                            if not string_struct:
                                break

                            ustr_offset = ( version_struct.OffsetToData + entry_offset +
                                string_struct.sizeof() )
                            try:
                                key = self.get_string_u_at_rva( ustr_offset )
                                key_offset = self.get_offset_from_rva( ustr_offset )
                            except PEFormatError as excp:
                                self.__warnings.append(
                                    'Error parsing the version information, '
                                    'attempting to read StringTable Key string. Can\'t '
                                    'read unicode string at offset 0x{0:x}'.format(ustr_offset))
                                break

                            value_offset = self.dword_align(
                                2*(len(key)+1) + entry_offset + string_struct.sizeof(),
                                version_struct.OffsetToData)

                            ustr_offset = version_struct.OffsetToData + value_offset
                            try:
                                value = self.get_string_u_at_rva( ustr_offset,
                                    max_length = string_struct.ValueLength )
                                value_offset = self.get_offset_from_rva( ustr_offset )
                            except PEFormatError as excp:
                                self.__warnings.append(
                                    'Error parsing the version information, '
                                    'attempting to read StringTable Value string. '
                                    'Can\'t read unicode string at offset 0x{0:x}'.format(
                                        ustr_offset))
                                break

                            if string_struct.Length == 0:
                                entry_offset = stringtable_offset + stringtable_struct.Length
                            else:
                                entry_offset = self.dword_align(
                                    string_struct.Length+entry_offset, version_struct.OffsetToData)

                            stringtable_struct.entries[key] = value
                            stringtable_struct.entries_offsets[key] = (key_offset, value_offset)
                            stringtable_struct.entries_lengths[key] = (len(key), len(value))


                        new_stringtable_offset = self.dword_align(
                            stringtable_struct.Length + stringtable_offset,
                            version_struct.OffsetToData)

                        # Check if the entry is crafted in a way that would lead
                        # to an infinite loop and break if so.
                        if new_stringtable_offset == stringtable_offset:
                            break
                        stringtable_offset = new_stringtable_offset

                        if stringtable_offset >= stringfileinfo_struct.Length:
                            break

            # Parse a VarFileInfo entry
            elif stringfileinfo_string and stringfileinfo_string.startswith( b'VarFileInfo' ):

                varfileinfo_struct = stringfileinfo_struct
                varfileinfo_struct.name = 'VarFileInfo'

                if varfileinfo_struct.Type in (0, 1) and varfileinfo_struct.ValueLength == 0:

                    var_offset = self.dword_align(
                        stringfileinfo_offset + varfileinfo_struct.sizeof() +
                            2*(len(stringfileinfo_string)+1),
                        version_struct.OffsetToData)

                    varfileinfo_struct.Var = list()

                    # Process all entries

                    while True:
                        var_struct = self.__unpack_data__(
                            self.__Var_format__,
                            raw_data[var_offset:],
                            file_offset = start_offset+var_offset )

                        if not var_struct:
                            break

                        ustr_offset = ( version_struct.OffsetToData + var_offset +
                            var_struct.sizeof() )
                        try:
                            var_string = self.get_string_u_at_rva( ustr_offset )
                        except PEFormatError as excp:
                            self.__warnings.append(
                                'Error parsing the version information, '
                                'attempting to read VarFileInfo Var string. '
                                'Can\'t read unicode string at offset 0x{0:x}'.format(ustr_offset))
                            break

                        if var_string is None:
                            break

                        varfileinfo_struct.Var.append(var_struct)

                        varword_offset = self.dword_align(
                            2*(len(var_string)+1) + var_offset + var_struct.sizeof(),
                            version_struct.OffsetToData)
                        orig_varword_offset = varword_offset

                        while varword_offset < orig_varword_offset + var_struct.ValueLength:
                            word1 = self.get_word_from_data(
                                raw_data[varword_offset:varword_offset+2], 0)
                            word2 = self.get_word_from_data(
                                raw_data[varword_offset+2:varword_offset+4], 0)
                            varword_offset += 4

                            if isinstance(word1, int) and isinstance(word2, int):
                                var_struct.entry = {var_string: '0x%04x 0x%04x' % (word1, word2)}

                        var_offset = self.dword_align(
                            var_offset+var_struct.Length, version_struct.OffsetToData)

                        if var_offset <= var_offset+var_struct.Length:
                            break


            # Increment and align the offset
            stringfileinfo_offset = self.dword_align(
                stringfileinfo_struct.Length+stringfileinfo_offset,
                version_struct.OffsetToData)

            # Check if all the StringFileInfo and VarFileInfo items have been processed
            if stringfileinfo_struct.Length == 0 or stringfileinfo_offset >= versioninfo_struct.Length:
                break


    def parse_export_directory(self, rva, size, forwarded_only=False):
        """Parse the export directory.

        Given the RVA of the export directory, it will process all
        its entries.

        The exports will be made available as a list of ExportData
        instances in the 'IMAGE_DIRECTORY_ENTRY_EXPORT' PE attribute.
        """

        try:
            export_dir =  self.__unpack_data__(
                self.__IMAGE_EXPORT_DIRECTORY_format__,
                self.get_data( rva, Structure(self.__IMAGE_EXPORT_DIRECTORY_format__).sizeof() ),
                file_offset = self.get_offset_from_rva(rva) )
        except PEFormatError:
            self.__warnings.append(
                'Error parsing export directory at RVA: 0x%x' % ( rva ) )
            return

        if not export_dir:
            return

        # We keep track of the bytes left in the file and use it to set a upper
        # bound in the number of items that can be read from the different
        # arrays.
        def length_until_eof(rva):
            return len(self.__data__) - self.get_offset_from_rva(rva)

        try:
            address_of_names = self.get_data(
                export_dir.AddressOfNames, min( length_until_eof(export_dir.AddressOfNames), export_dir.NumberOfNames*4))
            address_of_name_ordinals = self.get_data(
                export_dir.AddressOfNameOrdinals, min( length_until_eof(export_dir.AddressOfNameOrdinals), export_dir.NumberOfNames*4) )
            address_of_functions = self.get_data(
                export_dir.AddressOfFunctions, min( length_until_eof(export_dir.AddressOfFunctions), export_dir.NumberOfFunctions*4) )
        except PEFormatError:
            self.__warnings.append(
                'Error parsing export directory at RVA: 0x%x' % ( rva ) )
            return

        exports = []

        max_failed_entries_before_giving_up = 10

        section = self.get_section_by_rva(export_dir.AddressOfNames)
        if not section:
            self.__warnings.append(
                'RVA AddressOfNames in the export directory points to an invalid address: %x' %
                export_dir.AddressOfNames)
            return
        else:
            safety_boundary = section.VirtualAddress + len(section.get_data()) - export_dir.AddressOfNames

        for i in range(min(
                export_dir.NumberOfNames,
                int(safety_boundary / 4))):

            symbol_ordinal = self.get_word_from_data(
                address_of_name_ordinals, i)

            if symbol_ordinal is not None and symbol_ordinal*4 < len(address_of_functions):
                symbol_address = self.get_dword_from_data(
                    address_of_functions, symbol_ordinal)
            else:
                # Corrupt? a bad pointer... we assume it's all
                # useless, no exports
                return None

            if symbol_address is None or symbol_address == 0:
                continue

            # If the function's RVA points within the export directory
            # it will point to a string with the forwarded symbol's string
            # instead of pointing the the function start address.

            if symbol_address >= rva and symbol_address < rva+size:
                forwarder_str = self.get_string_at_rva(symbol_address)
                try:
                    forwarder_offset = self.get_offset_from_rva( symbol_address )
                except PEFormatError:
                    continue
            else:
                if forwarded_only:
                    continue
                forwarder_str = None
                forwarder_offset = None

            symbol_name_address = self.get_dword_from_data(address_of_names, i)

            if symbol_name_address is None:
                max_failed_entries_before_giving_up -= 1
                if max_failed_entries_before_giving_up <= 0:
                    break

            symbol_name = self.get_string_at_rva(symbol_name_address, MAX_SYMBOL_NAME_LENGTH)
            if not is_valid_function_name(symbol_name):
                break
            try:
                symbol_name_offset = self.get_offset_from_rva( symbol_name_address )
            except PEFormatError:
                max_failed_entries_before_giving_up -= 1
                if max_failed_entries_before_giving_up <= 0:
                    break
                continue

            exports.append(
                ExportData(
                    pe = self,
                    ordinal = export_dir.Base+symbol_ordinal,
                    ordinal_offset = self.get_offset_from_rva( export_dir.AddressOfNameOrdinals + 2*i ),
                    address = symbol_address,
                    address_offset = self.get_offset_from_rva( export_dir.AddressOfFunctions + 4*symbol_ordinal ),
                    name = symbol_name,
                    name_offset = symbol_name_offset,
                    forwarder = forwarder_str,
                    forwarder_offset = forwarder_offset ))

        ordinals = [exp.ordinal for exp in exports]

        max_failed_entries_before_giving_up = 10

        section = self.get_section_by_rva(export_dir.AddressOfFunctions)
        if not section:
            self.__warnings.append(
                'RVA AddressOfFunctions in the export directory points to an invalid address: %x' %
                export_dir.AddressOfFunctions)
            return
        else:
            safety_boundary = section.VirtualAddress + len(section.get_data()) - export_dir.AddressOfFunctions

        safety_boundary = section.VirtualAddress + len(section.get_data()) - export_dir.AddressOfFunctions

        for idx in range(min(
                export_dir.NumberOfFunctions,
                int(safety_boundary / 4))):

            if not idx+export_dir.Base in ordinals:
                try:
                    symbol_address = self.get_dword_from_data(
                        address_of_functions, idx)
                except PEFormatError:
                    symbol_address = None

                if symbol_address is None:
                    max_failed_entries_before_giving_up -= 1
                    if max_failed_entries_before_giving_up <= 0:
                        break

                if symbol_address == 0:
                    continue

                # Checking for forwarder again.
                if symbol_address >= rva and symbol_address < rva+size:
                    forwarder_str = self.get_string_at_rva(symbol_address)
                else:
                    forwarder_str = None

                exports.append(
                    ExportData(
                        ordinal = export_dir.Base+idx,
                        address = symbol_address,
                        name = None,
                        forwarder = forwarder_str))

        return ExportDirData(
                struct = export_dir,
                symbols = exports)


    def dword_align(self, offset, base):
        return ((offset+base+3) & 0xfffffffc) - (base & 0xfffffffc)


    def parse_delay_import_directory(self, rva, size):
        """Walk and parse the delay import directory."""

        import_descs =  []
        error_count = 0
        while True:
            try:
                # If the RVA is invalid all would blow up. Some PEs seem to be
                # specially nasty and have an invalid RVA.
                data = self.get_data( rva, Structure(self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__).sizeof() )
            except PEFormatError as e:
                self.__warnings.append(
                    'Error parsing the Delay import directory at RVA: 0x%x' % ( rva ) )
                break

            file_offset = self.get_offset_from_rva(rva)
            import_desc =  self.__unpack_data__(
                self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__,
                data, file_offset = file_offset )


            # If the structure is all zeros, we reached the end of the list
            if not import_desc or import_desc.all_zeroes():
                break


            rva += import_desc.sizeof()

            # If the array of thunk's is somewhere earlier than the import
            # descriptor we can set a maximum length for the array. Otherwise
            # just set a maximum length of the size of the file
            max_len = len(self.__data__) - file_offset
            if rva > import_desc.pINT or rva > import_desc.pIAT:
                max_len = max(rva-import_desc.pINT, rva-import_desc.pIAT)

            import_data = []
            try:
                import_data =  self.parse_imports(
                    import_desc.pINT,
                    import_desc.pIAT,
                    None,
                    max_length = max_len)
            except PEFormatError as e:
                self.__warnings.append(
                    'Error parsing the Delay import directory. '
                    'Invalid import data at RVA: 0x{0:x} ({1})'.format(
                        rva, e.value))

            if error_count > 5:
                self.__warnings.append(
                    'Too may errors parsing the Delay import directory. '
                    'Invalid import data at RVA: 0x{0:x}'.format(rva) )
                break

            if not import_data:
                error_count += 1
                continue

            dll = self.get_string_at_rva(import_desc.szName, MAX_DLL_LENGTH)
            if not is_valid_dos_filename(dll):
                dll = b('*invalid*')

            if dll:
                for symbol in import_data:
                    if symbol.name is None:
                        funcname = ordlookup.ordLookup(dll.lower(), symbol.ordinal)
                        if funcname:
                            symbol.name = funcname
                import_descs.append(
                    ImportDescData(
                        struct = import_desc,
                        imports = import_data,
                        dll = dll))

        return import_descs


    def parse_import_directory(self, rva, size, dllnames_only=False):
        """Walk and parse the import directory."""

        import_descs =  []
        error_count = 0
        while True:
            try:
                # If the RVA is invalid all would blow up. Some EXEs seem to be
                # specially nasty and have an invalid RVA.
                data = self.get_data(rva, Structure(
                        self.__IMAGE_IMPORT_DESCRIPTOR_format__).sizeof() )
            except PEFormatError as e:
                self.__warnings.append(
                    'Error parsing the import directory at RVA: 0x%x' % ( rva ) )
                break

            file_offset = self.get_offset_from_rva(rva)
            import_desc =  self.__unpack_data__(
                self.__IMAGE_IMPORT_DESCRIPTOR_format__,
                data, file_offset = file_offset )

            # If the structure is all zeros, we reached the end of the list
            if not import_desc or import_desc.all_zeroes():
                break

            rva += import_desc.sizeof()

            # If the array of thunk's is somewhere earlier than the import
            # descriptor we can set a maximum length for the array. Otherwise
            # just set a maximum length of the size of the file
            max_len = len(self.__data__) - file_offset
            if rva > import_desc.OriginalFirstThunk or rva > import_desc.FirstThunk:
                max_len = max(rva-import_desc.OriginalFirstThunk, rva-import_desc.FirstThunk)

            import_data = []
            if not dllnames_only:
                try:
                    import_data =  self.parse_imports(
                        import_desc.OriginalFirstThunk,
                        import_desc.FirstThunk,
                        import_desc.ForwarderChain,
                        max_length = max_len)
                except PEFormatError as e:
                    self.__warnings.append(
                        'Error parsing the import directory. '
                        'Invalid Import data at RVA: 0x{0:x} ({1})'.format(
                            rva, e.value))

                if error_count > 5:
                    self.__warnings.append(
                        'Too may errors parsing the import directory. '
                        'Invalid import data at RVA: 0x{0:x}'.format(rva) )
                    break

                if not import_data:
                    error_count += 1
                    # TODO: do not continue here
                    continue

            dll = self.get_string_at_rva(import_desc.Name, MAX_DLL_LENGTH)
            if not is_valid_dos_filename(dll):
                dll = b('*invalid*')

            if dll:
                for symbol in import_data:
                    if symbol.name is None:
                        funcname = ordlookup.ordLookup(dll.lower(), symbol.ordinal)
                        if funcname:
                            symbol.name = funcname
                import_descs.append(
                    ImportDescData(
                        struct = import_desc,
                        imports = import_data,
                        dll = dll))

        if not dllnames_only:
            suspicious_imports = set([ u'LoadLibrary', u'GetProcAddress' ])
            suspicious_imports_count = 0
            total_symbols = 0
            for imp_dll in import_descs:
                for symbol in imp_dll.imports:
                    for suspicious_symbol in suspicious_imports:
                        if symbol and symbol.name and symbol.name.startswith(
                            b(suspicious_symbol)):
                            suspicious_imports_count += 1
                            break
                    total_symbols += 1
            if suspicious_imports_count == len(suspicious_imports) and total_symbols < 20:
                self.__warnings.append(
                    'Imported symbols contain entries typical of packed executables.' )

        return import_descs



    def parse_imports(
            self, original_first_thunk, first_thunk,
            forwarder_chain, max_length=None):
        """Parse the imported symbols.

        It will fill a list, which will be available as the dictionary
        attribute "imports". Its keys will be the DLL names and the values
        all the symbols imported from that object.
        """

        imported_symbols = []

        # The following has been commented as a PE does not
        # need to have the import data necessarily within
        # a section, it can keep it in gaps between sections
        # or overlapping other data.
        #
        #imports_section = self.get_section_by_rva(first_thunk)
        #if not imports_section:
        #    raise PEFormatError, 'Invalid/corrupt imports.'

        # Import Lookup Table. Contains ordinals or pointers to strings.
        ilt = self.get_import_table(original_first_thunk, max_length)
        # Import Address Table. May have identical content to ILT if
        # PE file is not bounded, Will contain the address of the
        # imported symbols once the binary is loaded or if it is already
        # bound.
        iat = self.get_import_table(first_thunk, max_length)

        # OC Patch:
        # Would crash if IAT or ILT had None type
        if (not iat or len(iat)==0) and (not ilt or len(ilt)==0):
            self.__warnings.append(
                'Damaged Import Table information. '
                'ILT and/or IAT appear to be broken. '
                'OriginalFirstThunk: 0x{0:x} FirstThunk: 0x{1:x}'.format(
                    original_first_thunk, first_thunk))
            return []

        table = None
        if ilt:
            table = ilt
        elif iat:
            table = iat
        else:
            return None

        imp_offset = 4
        address_mask = 0x7fffffff
        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            ordinal_flag = IMAGE_ORDINAL_FLAG
        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            ordinal_flag = IMAGE_ORDINAL_FLAG64
            imp_offset = 8
            address_mask = 0x7fffffffffffffff
        else:
            # Some PEs may have an invalid value in the Magic field of the
            # Optional Header. Just in case the remaining file is parseable
            # let's pretend it's a 32bit PE32 by default.
            ordinal_flag = IMAGE_ORDINAL_FLAG

        num_invalid = 0
        for idx in range(len(table)):
            imp_ord = None
            imp_hint = None
            imp_name = None
            name_offset = None
            hint_name_table_rva = None

            if table[idx].AddressOfData:
                # If imported by ordinal, we will append the ordinal number
                #
                if table[idx].AddressOfData & ordinal_flag:
                    import_by_ordinal = True
                    imp_ord = table[idx].AddressOfData & 0xffff
                    imp_name = None
                    name_offset = None
                else:
                    import_by_ordinal = False
                    try:
                        hint_name_table_rva = table[idx].AddressOfData & address_mask
                        data = self.get_data(hint_name_table_rva, 2)
                        # Get the Hint
                        imp_hint = self.get_word_from_data(data, 0)
                        imp_name = self.get_string_at_rva(table[idx].AddressOfData+2, MAX_IMPORT_NAME_LENGTH)
                        if not is_valid_function_name(imp_name):
                            imp_name = b('*invalid*')

                        name_offset = self.get_offset_from_rva(table[idx].AddressOfData+2)
                    except PEFormatError as e:
                        pass

                # by nriva: we want the ThunkRVA and ThunkOffset
                thunk_offset = table[idx].get_file_offset()
                thunk_rva = self.get_rva_from_offset(thunk_offset)

            imp_address = first_thunk + self.OPTIONAL_HEADER.ImageBase + idx * imp_offset

            struct_iat = None
            try:
                if iat and ilt and ilt[idx].AddressOfData != iat[idx].AddressOfData:
                    imp_bound = iat[idx].AddressOfData
                    struct_iat = iat[idx]
                else:
                    imp_bound = None
            except IndexError:
                imp_bound = None

            # The file with hashes:
            #
            # MD5: bfe97192e8107d52dd7b4010d12b2924
            # SHA256: 3d22f8b001423cb460811ab4f4789f277b35838d45c62ec0454c877e7c82c7f5
            #
            # has an invalid table built in a way that it's parseable but contains invalid
            # entries that lead pefile to take extremely long amounts of time to
            # parse. It also leads to extreme memory consumption.
            # To prevent similar cases, if invalid entries are found in the middle of a
            # table the parsing will be aborted
            #
            if imp_ord == None and imp_name == None:
                raise PEFormatError('Invalid entries, aborting parsing.')

            # Some PEs appear to interleave valid and invalid imports. Instead of
            # aborting the parsing altogether we will simply skip the invalid entries.
            # Although if we see 1000 invalid entries and no legit ones, we abort.
            if imp_name == b('*invalid*'):
                if num_invalid > 1000 and num_invalid == idx:
                    raise PEFormatError('Too many invalid names, aborting parsing.')
                num_invalid += 1
                continue

            if imp_name != '' and (imp_ord or imp_name):
                imported_symbols.append(
                    ImportData(
                    pe = self,
                        struct_table = table[idx],
                        struct_iat = struct_iat, # for bound imports if any
                        import_by_ordinal = import_by_ordinal,
                        ordinal = imp_ord,
                        ordinal_offset = table[idx].get_file_offset(),
                        hint = imp_hint,
                        name = imp_name,
                        name_offset = name_offset,
                        bound = imp_bound,
                        address = imp_address,
                        hint_name_table_rva = hint_name_table_rva,
                        thunk_offset = thunk_offset,
                        thunk_rva = thunk_rva ))

        return imported_symbols



    def get_import_table(self, rva, max_length=None):

        table = []

        # We need the ordinal flag for a simple heuristic
        # we're implementing within the loop
        #
        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            ordinal_flag = IMAGE_ORDINAL_FLAG
            format = self.__IMAGE_THUNK_DATA_format__
        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            ordinal_flag = IMAGE_ORDINAL_FLAG64
            format = self.__IMAGE_THUNK_DATA64_format__
        else:
            # Some PEs may have an invalid value in the Magic field of the
            # Optional Header. Just in case the remaining file is parseable
            # let's pretend it's a 32bit PE32 by default.
            ordinal_flag = IMAGE_ORDINAL_FLAG
            format = self.__IMAGE_THUNK_DATA_format__


        MAX_ADDRESS_SPREAD = 128*2**20 # 64 MB
        MAX_REPEATED_ADDRESSES = 15
        repeated_address = 0
        addresses_of_data_set_64 = set()
        addresses_of_data_set_32 = set()
        start_rva = rva
        while True and rva:
            if max_length is not None and rva >= start_rva+max_length:
                self.__warnings.append(
                    'Error parsing the import table. Entries go beyond bounds.')
                break

            # if we see too many times the same entry we assume it could be
            # a table containing bogus data (with malicious intent or otherwise)
            if repeated_address >= MAX_REPEATED_ADDRESSES:
                return []

            # if the addresses point somewhere but the difference between the highest
            # and lowest address is larger than MAX_ADDRESS_SPREAD we assume a bogus
            # table as the addresses should be contained within a module
            if (addresses_of_data_set_32 and
                max(addresses_of_data_set_32) - min(addresses_of_data_set_32) > MAX_ADDRESS_SPREAD ):
                return []
            if (addresses_of_data_set_64 and
                max(addresses_of_data_set_64) - min(addresses_of_data_set_64) > MAX_ADDRESS_SPREAD ):
                return []

            failed = False
            try:
                data = self.get_data(rva, Structure(format).sizeof())
            except PEFormatError as e:
                failed = True

            if failed or len(data) != Structure(format).sizeof():
                self.__warnings.append(
                    'Error parsing the import table. '
                    'Invalid data at RVA: 0x%x' % rva)
                return None

            thunk_data = self.__unpack_data__(
                format, data, file_offset=self.get_offset_from_rva(rva) )

            # Check if the AddressOfData lies within the range of RVAs that it's
            # being scanned, abort if that is the case, as it is very unlikely
            # to be legitimate data.
            # Seen in PE with SHA256:
            # 5945bb6f0ac879ddf61b1c284f3b8d20c06b228e75ae4f571fa87f5b9512902c
            if thunk_data and thunk_data.AddressOfData >= start_rva and thunk_data.AddressOfData <= rva:
                self.__warnings.append(
                    'Error parsing the import table. '
                    'AddressOfData overlaps with THUNK_DATA for '
                    'THUNK at RVA 0x%x' % ( rva ) )
                break

            if thunk_data and thunk_data.AddressOfData:
                # If the entry looks like could be an ordinal...
                if thunk_data.AddressOfData & ordinal_flag:
                    # but its value is beyond 2^16, we will assume it's a
                    # corrupted and ignore it altogether
                    if thunk_data.AddressOfData & 0x7fffffff > 0xffff:
                        return []
                # and if it looks like it should be an RVA
                else:
                    # keep track of the RVAs seen and store them to study their
                    # properties. When certain non-standard features are detected
                    # the parsing will be aborted
                    if (thunk_data.AddressOfData in addresses_of_data_set_32 or
                        thunk_data.AddressOfData in addresses_of_data_set_64):
                        repeated_address += 1
                    if thunk_data.AddressOfData >= 2**32:
                        addresses_of_data_set_64.add(thunk_data.AddressOfData)
                    else:
                        addresses_of_data_set_32.add(thunk_data.AddressOfData)

            if not thunk_data or thunk_data.all_zeroes():
                break

            rva += thunk_data.sizeof()

            table.append(thunk_data)

        return table


    def get_resources_strings(self):
        """Returns a list of all the strings found withing the resources (if any).

        This method will scan all entries in the resources directory of the PE, if
        there is one, and will return a list() with the strings.

        An empty list will be returned otherwise.
        """

        resources_strings = list()

        if hasattr(self, 'DIRECTORY_ENTRY_RESOURCE'):

            for resource_type in self.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            if hasattr(resource_id.directory, 'strings') and resource_id.directory.strings:
                                for res_string in list(resource_id.directory.strings.values()):
                                    resources_strings.append( res_string )

        return resources_strings


    def get_data(self, rva=0, length=None):
        """Get data regardless of the section where it lies on.

        Given a RVA and the size of the chunk to retrieve, this method
        will find the section where the data lies and return the data.
        """

        s = self.get_section_by_rva(rva)

        if length:
            end = rva + length
        else:
            end = None

        if not s:
            if rva < len(self.header):
                return self.header[rva:end]

            # Before we give up we check whether the file might
            # contain the data anyway. There are cases of PE files
            # without sections that rely on windows loading the first
            # 8291 bytes into memory and assume the data will be
            # there
            # A functional file with these characteristics is:
            # MD5: 0008892cdfbc3bda5ce047c565e52295
            # SHA-1: c7116b9ff950f86af256defb95b5d4859d4752a9
            #
            if rva < len(self.__data__):
                return self.__data__[rva:end]

            raise PEFormatError('data at RVA can\'t be fetched. Corrupt header?')

        return s.get_data(rva, length)


    def get_rva_from_offset(self, offset):
        """Get the RVA corresponding to this file offset. """

        s = self.get_section_by_offset(offset)
        if not s:
            if self.sections:
                lowest_rva = min( [ self.adjust_SectionAlignment( s.VirtualAddress,
                    self.OPTIONAL_HEADER.SectionAlignment, self.OPTIONAL_HEADER.FileAlignment ) for s in self.sections] )
                if offset < lowest_rva:
                    # We will assume that the offset lies within the headers, or
                    # at least points before where the earliest section starts
                    # and we will simply return the offset as the RVA
                    #
                    # The case illustrating this behavior can be found at:
                    # http://corkami.blogspot.com/2010/01/hey-hey-hey-whats-in-your-head.html
                    # where the import table is not contained by any section
                    # hence the RVA needs to be resolved to a raw offset
                    return offset
                return None
            else:
                return offset
            #raise PEFormatError("specified offset (0x%x) doesn't belong to any section." % offset)
        return s.get_rva_from_offset(offset)

    def get_offset_from_rva(self, rva):
        """Get the file offset corresponding to this RVA.

        Given a RVA , this method will find the section where the
        data lies and return the offset within the file.
        """

        s = self.get_section_by_rva(rva)
        if not s:

            # If not found within a section assume it might
            # point to overlay data or otherwise data present
            # but not contained in any section. In those
            # cases the RVA should equal the offset
            if rva < len(self.__data__):
                return rva

            raise PEFormatError('data at RVA can\'t be fetched. Corrupt header?')

        return s.get_offset_from_rva(rva)


    def get_string_at_rva(self, rva, max_length=MAX_STRING_LENGTH):
        """Get an ASCII string located at the given address."""

        if rva is None:
            return None

        s = self.get_section_by_rva(rva)
        if not s:
            return self.get_string_from_data(0, self.__data__[rva:rva+max_length])
        return self.get_string_from_data(0, s.get_data(rva, length=max_length))

    def get_bytes_from_data(self, offset, data):
        """."""
        if offset > len(data):
            return b''
        return data[offset:]

    def get_string_from_data(self, offset, data):
        """Get an ASCII string from data."""
        s = self.get_bytes_from_data(offset, data)
        end = s.find(b'\0')
        if end >= 0:
            s = s[:end]
        return s #.decode('ascii', 'backslashreplace')

    def get_string_u_at_rva(self, rva, max_length = 2**16, encoding=None):
        """Get an Unicode string located at the given address."""

        try:
            # If the RVA is invalid all would blow up. Some EXEs seem to be
            # specially nasty and have an invalid RVA.
            data = self.get_data(rva, 2)
        except PEFormatError as e:
            return None
        # max_length is the maximum count of 16bit characters
        # needs to be doubled to get size in bytes
        max_length <<= 1

        requested = min(max_length, 256)
        data = self.get_data(rva, requested)
        # try to find null-termination
        null_index = -1
        while True:
            null_index = data.find(b'\x00\x00', null_index + 1)
            if null_index == -1:
                data_length = len(data)
                if data_length < requested or data_length == max_length:
                    null_index = len(data) >> 1
                    break
                else:
                    # Request remaining part of data limited by max_length
                    data += self.get_data(rva + data_length, max_length - data_length)
                    null_index = requested - 1
                    requested = max_length

            elif null_index % 2 == 0:
                null_index >>= 1
                break

        # convert selected part of the string to unicode
        uchrs = struct.unpack('<{:d}H'.format(null_index), data[:null_index * 2])
        s = u''.join(map(chr, uchrs))

        if encoding:
            return b(s.encode(encoding, 'backslashreplace'))

        return b(s.encode('utf-8', 'backslashreplace'))


    def get_section_by_offset(self, offset):
        """Get the section containing the given file offset."""

        sections = [s for s in self.sections if s.contains_offset(offset)]

        if sections:
            return sections[0]

        return None


    def get_section_by_rva(self, rva):
        """Get the section containing the given address."""

        sections = [s for s in self.sections if s.contains_rva(rva)]

        if sections:
            return sections[0]

        return None


    ##
    # Double-Word get / set
    ##

    def get_data_from_dword(self, dword):
        """Return a four byte string representing the double word value. (little endian)."""
        return struct.pack('<L', dword & 0xffffffff)


    def get_dword_from_data(self, data, offset):
        """Convert four bytes of data to a double word (little endian)

        'offset' is assumed to index into a dword array. So setting it to
        N will return a dword out of the data starting at offset N*4.

        Returns None if the data can't be turned into a double word.
        """

        if (offset+1)*4 > len(data):
            return None

        return struct.unpack('<I', data[offset*4:(offset+1)*4])[0]


    ##
    # Word get / set
    ##

    def get_data_from_word(self, word):
        """Return a two byte string representing the word value. (little endian)."""
        return struct.pack('<H', word)


    def get_word_from_data(self, data, offset):
        """Convert two bytes of data to a word (little endian)

        'offset' is assumed to index into a word array. So setting it to
        N will return a dword out of the data starting at offset N*2.

        Returns None if the data can't be turned into a word.
        """

        if (offset+1)*2 > len(data):
            return None

        return struct.unpack('<H', data[offset*2:(offset+1)*2])[0]


    # According to http://corkami.blogspot.com/2010/01/parce-que-la-planche-aura-brule.html
    # if PointerToRawData is less that 0x200 it's rounded to zero. Loading the test file
    # in a debugger it's easy to verify that the PointerToRawData value of 1 is rounded
    # to zero. Hence we reproduce the behavior
    #
    # According to the document:
    # [ Microsoft Portable Executable and Common Object File Format Specification ]
    # "The alignment factor (in bytes) that is used to align the raw data of sections in
    #  the image file. The value should be a power of 2 between 512 and 64 K, inclusive.
    #  The default is 512. If the SectionAlignment is less than the architecture's page
    #  size, then FileAlignment must match SectionAlignment."
    #
    # The following is a hard-coded constant if the Windows loader
    def adjust_FileAlignment( self, val, file_alignment ):
        return val


    # According to the document:
    # [ Microsoft Portable Executable and Common Object File Format Specification ]
    # "The alignment (in bytes) of sections when they are loaded into memory. It must be
    #  greater than or equal to FileAlignment. The default is the page size for the
    #  architecture."
    #
    def adjust_SectionAlignment( self, val, section_alignment, file_alignment ):
        global SectionAlignment_Warning
        if file_alignment < FILE_ALIGNEMNT_HARDCODED_VALUE:
            if file_alignment != section_alignment and SectionAlignment_Warning is False:
                self.__warnings.append(
                    'If FileAlignment(%x) < 0x200 it should equal SectionAlignment(%x)' % (
                        file_alignment, section_alignment)  )
                SectionAlignment_Warning = True

        if section_alignment < 0x1000: # page size
            section_alignment = file_alignment

        # 0x200 is the minimum valid FileAlignment according to the documentation
        # although ntoskrnl.exe has an alignment of 0x80 in some Windows versions
        #
        #elif section_alignment < 0x80:
        #    section_alignment = 0x80

        if section_alignment and val % section_alignment:
            return section_alignment * ( int(val / section_alignment) )
        return val
