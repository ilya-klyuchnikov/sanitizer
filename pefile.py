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
import string
import mmap

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


class PEFormatError(Exception):
    """Generic PE format error exception."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


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


class DataContainer(object):
    """Generic data container."""

    def __init__(self, **args):
        bare_setattr = super(DataContainer, self).__setattr__
        for key, value in list(args.items()):
            bare_setattr(key, value)

class DebugData(DataContainer):
    """Holds debug information.

    struct:     IMAGE_DEBUG_DIRECTORY structure
    entries:    list of entries (IMAGE_DEBUG_TYPE instances)
    """


class PE(object):

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

    # TODO - check FileAlignment
    __IMAGE_OPTIONAL_HEADER_format__ = ('IMAGE_OPTIONAL_HEADER',
        ('H,Magic', 'B,MajorLinkerVersion',
        'B,MinorLinkerVersion', 'I,SizeOfCode',
        'I,SizeOfInitializedData', 'I,SizeOfUninitializedData',
        'I,AddressOfEntryPoint', 'I,BaseOfCode', 'I,BaseOfData', #see BaseOfData in next
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

    __IMAGE_IMPORT_DESCRIPTOR_format__ = ('IMAGE_IMPORT_DESCRIPTOR',
        ('I,OriginalFirstThunk,Characteristics',
        'I,TimeDateStamp', 'I,ForwarderChain', 'I,Name', 'I,FirstThunk'))

    __IMAGE_EXPORT_DIRECTORY_format__ = ('IMAGE_EXPORT_DIRECTORY',
        ('I,Characteristics',
        'I,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion', 'I,Name',
        'I,Base', 'I,NumberOfFunctions', 'I,NumberOfNames',
        'I,AddressOfFunctions', 'I,AddressOfNames', 'I,AddressOfNameOrdinals'))

    __IMAGE_RESOURCE_DIRECTORY_format__ = ('IMAGE_RESOURCE_DIRECTORY',
        ('I,Characteristics',
        'I,TimeDateStamp', 'H,MajorVersion', 'H,MinorVersion',
        'H,NumberOfNamedEntries', 'H,NumberOfIdEntries'))

    __IMAGE_DEBUG_DIRECTORY_format__ = ('IMAGE_DEBUG_DIRECTORY',
        ('I,Characteristics', 'I,TimeDateStamp', 'H,MajorVersion',
        'H,MinorVersion', 'I,Type', 'I,SizeOfData', 'I,AddressOfRawData',
        'I,PointerToRawData'))

    __IMAGE_BASE_RELOCATION_format__ = ('IMAGE_BASE_RELOCATION',
        ('I,VirtualAddress', 'I,SizeOfBlock') )

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

        ## TODO - check that they are not overlapping
        ## TODO - if they are not overlapping - a lot of simplifications
        for i in range(int(0x7fffffff & self.OPTIONAL_HEADER.NumberOfRvaAndSizes)):
            my_descr = Structure(self.__IMAGE_DATA_DIRECTORY_format__)
            my_descr_size = my_descr.sizeof()
            data = self.__data__[offset:offset+my_descr_size]

            dir_entry = self.__unpack_data__(
                self.__IMAGE_DATA_DIRECTORY_format__,
                data,
                file_offset = offset)
            dir_entry.name = DIRECTORY_ENTRY[i]
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
        for i in range(self.FILE_HEADER.NumberOfSections):
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
            ('IMAGE_DIRECTORY_ENTRY_RESOURCE', self.parse_resources_directory),
            ('IMAGE_DIRECTORY_ENTRY_DEBUG', self.parse_debug_directory),
            ('IMAGE_DIRECTORY_ENTRY_BASERELOC', self.parse_relocations_directory),
            ('IMAGE_DIRECTORY_ENTRY_TLS', self.parse_directory_tls),
            ('IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG', self.parse_directory_load_config),
            ('IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT', self.parse_delay_import_directory),
            ('IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT', self.parse_directory_bound_imports) )

        for entry in directory_parsing:
            try:
                directory_index = DIRECTORY_ENTRY[entry[0]]
                dir_entry = self.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
            except IndexError:
                break

            if dir_entry.VirtualAddress:
                entry[1](dir_entry.VirtualAddress, dir_entry.Size)

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
            self.__unpack_data__(
                format,
                self.get_data( rva, Structure(format).sizeof() ),
                file_offset = self.get_offset_from_rva(rva))
        except PEFormatError:
            self.__warnings.append(
                'Invalid TLS information. Can\'t read '
                'data at RVA: 0x%x' % rva)


    def parse_directory_load_config(self, rva, size):
        """"""

        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            format = self.__IMAGE_LOAD_CONFIG_DIRECTORY_format__

        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            format = self.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__

        try:
            self.__unpack_data__(
                format,
                self.get_data( rva, Structure(format).sizeof() ),
                file_offset = self.get_offset_from_rva(rva))
        except PEFormatError:
            self.__warnings.append(
                'Invalid LOAD_CONFIG information. Can\'t read '
                'data at RVA: 0x%x' % rva)

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
                break

            # rlc.SizeOfBlock must be less or equal than the size of the image
            # (It's a rather loose sanity test)
            if rlc.SizeOfBlock > self.OPTIONAL_HEADER.SizeOfImage:
                break

            if rlc.SizeOfBlock == 0:
                break

            rva += rlc.SizeOfBlock

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
                    # TODO - Hey
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

    def parse_resources_directory(self, rva, size=0, base_rva = None, level = 0, dirs=None):
        """Parse the resources directory.

        Given the RVA of the resources directory, it will process all
        its entries.

        The root will have the corresponding member of its structure,
        IMAGE_RESOURCE_DIRECTORY plus 'entries', a list of all the
        entries in the directory.

        Those entries will have, correspondingly, all the structure's
        members (IMAGE_RESOURCE_DIRECTORY_ENTRY) and an additional one,
        "directory", pointing to the IMAGE_RESOURCE_DIRECTORY structure
        representing upper layers of the tree. This one will also have
        an 'entries' attribute, pointing to the 3rd, and last, level.
        Another directory with more entries. Those last entries will
        have a new attribute (both 'leaf' or 'data_entry' can be used to
        access it). This structure finally points to the resource data.
        All the members of this structure, IMAGE_RESOURCE_DATA_ENTRY,
        are available as its attributes.
        """

        try:
            # If the RVA is invalid all would blow up. Some EXEs seem to be
            # specially nasty and have an invalid RVA.
            data = self.get_data(rva, Structure(self.__IMAGE_RESOURCE_DIRECTORY_format__).sizeof() )
        except PEFormatError as e:
            self.__warnings.append(
                'Invalid resources directory. Can\'t read '
                'directory data at RVA: 0x%x' % rva)
            return None

        # Get the resource directory structure, that is, the header
        # of the table preceding the actual entries
        #
        resource_dir = self.__unpack_data__(
            self.__IMAGE_RESOURCE_DIRECTORY_format__, data,
            file_offset = self.get_offset_from_rva(rva) )
        if resource_dir is None:
            # If can't parse resources directory then silently return.
            # This directory does not necessarily have to be valid to
            # still have a valid PE file
            self.__warnings.append(
                'Invalid resources directory. Can\'t parse '
                'directory data at RVA: 0x%x' % rva)
            return None


    def parse_export_directory(self, rva, size, forwarded_only=False):
        """Parse the export directory.

        Given the RVA of the export directory, it will process all
        its entries.

        The exports will be made available as a list of ExportData
        instances in the 'IMAGE_DIRECTORY_ENTRY_EXPORT' PE attribute.
        """

        try:
            self.__unpack_data__(
                self.__IMAGE_EXPORT_DIRECTORY_format__,
                self.get_data( rva, Structure(self.__IMAGE_EXPORT_DIRECTORY_format__).sizeof() ),
                file_offset = self.get_offset_from_rva(rva) )
        except PEFormatError:
            self.__warnings.append(
                'Error parsing export directory at RVA: 0x%x' % ( rva ) )


    def parse_delay_import_directory(self, rva, size):
        """Walk and parse the delay import directory."""
        while True:
            try:
                # If the RVA is invalid all would blow up. Some PEs seem to be
                # specially nasty and have an invalid RVA.
                data = self.get_data(rva, Structure(self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__).sizeof())
            except PEFormatError as e:
                self.__warnings.append(
                    'Error parsing the Delay import directory at RVA: 0x%x' % ( rva ) )
                break

            file_offset = self.get_offset_from_rva(rva)
            import_desc = self.__unpack_data__(
                self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__,
                data, file_offset = file_offset )

            # If the structure is all zeros, we reached the end of the list
            if not import_desc or import_desc.all_zeroes():
                break

            rva += import_desc.sizeof()


    def parse_import_directory(self, rva, size, dllnames_only=False):
        """Walk and parse the import directory."""
        while True:
            try:
                # If the RVA is invalid all would blow up. Some EXEs seem to be
                # specially nasty and have an invalid RVA.
                data = self.get_data(rva, Structure(self.__IMAGE_IMPORT_DESCRIPTOR_format__).sizeof())
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
    def adjust_FileAlignment(self, pointer_to_raw_data, file_alignment):
        # TODO - possibly 0x1000?
        if file_alignment < FILE_ALIGNEMNT_HARDCODED_VALUE:
            return pointer_to_raw_data
        return (int(pointer_to_raw_data / 0x200)) * 0x200


    # According to the document:
    # [ Microsoft Portable Executable and Common Object File Format Specification ]
    # "The alignment (in bytes) of sections when they are loaded into memory. It must be
    #  greater than or equal to FileAlignment. The default is the page size for the
    #  architecture."
    #
    def adjust_SectionAlignment(self, virtual_address, section_alignment, file_alignment):
        if section_alignment < 0x1000: # page size
            section_alignment = file_alignment

        if section_alignment and virtual_address % section_alignment:
            return section_alignment * (int(virtual_address / section_alignment))
        return virtual_address
