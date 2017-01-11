# https://msdn.microsoft.com/en-us/library/ba1z7822.aspx#Example
# https://msdn.microsoft.com/en-us/library/2kzt1wy3(v=vs.80).aspx - very interesting

import obj
import pefile
import subprocess
import shutil
import os
import time

# currently I assume SDK 10.0.10586.0
# TODO - generalize to test with different versions

# paths with lib files for linking 64bit apps with VS 2015 and Windows SDK 10.0.10586.0
LIBPATH_FLAGS = [
  '/LIBPATH:C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\LIB\\amd64',
  '/LIBPATH:C:\\Program Files (x86)\\Windows Kits\\10\\lib\\10.0.10586.0\\ucrt\\x64',
  '/LIBPATH:C:\\Program Files (x86)\\Windows Kits\\10\\lib\\10.0.10586.0\\um\\x64',
]

# paths with header files for compiling with VS 2015 and Windows SDK 10.0.10586.0
INCLUDE_FLAGS = [
  '/IC:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\include',
  '/IC:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.10586.0\\ucrt',
  '/IC:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.10586.0\\um',
  '/IC:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.10586.0\\shared',
]

CL_EXE = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\bin\\amd64\\cl.exe"
LIB_EXE = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\bin\\amd64\\lib.exe"
LINK_EXE = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\bin\\amd64\\link.exe"

VERBOSE = False
TEST = True


def verbose(msg):
    if VERBOSE:
        print msg


def build_obj(input_file, output_file, extra_flags=[]):
    flags = [
        '/nologo',
        '/c',
        '/Fo:{0}'.format(output_file),
        input_file,
    ]
    command = [CL_EXE] + INCLUDE_FLAGS + flags + extra_flags
    verbose(command)
    result = subprocess.call(command)
    assert result == 0


def link_exe(obj_files, output_file):
    command = [LINK_EXE] + LIBPATH_FLAGS + obj_files + ['/out:{0}'.format(output_file)]
    verbose(command)
    result = subprocess.call(command)
    assert result == 0


def link_dll(obj_files, output_file):
    command = [LINK_EXE, '/dll'] + LIBPATH_FLAGS + obj_files + ['/out:{0}'.format(output_file)]
    verbose(command)
    result = subprocess.call(command)
    assert result == 0


def compare_files(f1, f2):
    with open(f1, 'rb') as file1, open(f2, 'rb') as file2:
        return file1.read() == file2.read()


def run_tests():

    shutil.rmtree('tmp_projects', ignore_errors=True)
    os.makedirs('tmp_projects')

    build_obj(
        'testdata-projects/01-main/lib.c', 'tmp_projects/lib.obj'
    )

    build_obj(
        'testdata-projects/01-main/main.c', 'tmp_projects/main.obj'
    )

    obj.strip('tmp_projects/lib.obj', 'tmp_projects/lib-stripped.obj')
    obj.strip('tmp_projects/main.obj', 'tmp_projects/main-stripped.obj')

    link_exe(['tmp_projects/lib-stripped.obj', 'tmp_projects/main-stripped.obj'], 'tmp_projects/main-stripped.exe')
    link_dll(['tmp_projects/lib-stripped.obj', 'tmp_projects/main-stripped.obj'], 'tmp_projects/main-stripped.dll')
    time.sleep(5)
    link_exe(['tmp_projects/lib.obj', 'tmp_projects/main.obj'], 'tmp_projects/main.exe')
    link_dll(['tmp_projects/lib.obj', 'tmp_projects/main.obj'], 'tmp_projects/main.dll')

    pe = pefile.PE('tmp_projects/main.exe')
    pe.default_timestamp()
    pe.write('tmp_projects/main-fixed.exe')

    pe = pefile.PE('tmp_projects/main.dll')
    pe.default_timestamp()
    pe.write('tmp_projects/main-fixed.dll')

    pe = pefile.PE('tmp_projects/main-stripped.exe')
    pe.default_timestamp()
    pe.write('tmp_projects/main-stripped-fixed.exe')

    pe = pefile.PE('tmp_projects/main-stripped.dll')
    pe.default_timestamp()
    pe.write('tmp_projects/main-stripped-fixed.dll')

    assert compare_files('tmp_projects/main-fixed.exe', 'tmp_projects/main-stripped-fixed.exe')
    assert compare_files('testdata-projects/01-main/main-fixed.exe', 'tmp_projects/main-fixed.exe')

    assert compare_files('tmp_projects/main-fixed.dll', 'tmp_projects/main-stripped-fixed.dll')
    assert compare_files('testdata-projects/01-main/main-fixed.dll', 'tmp_projects/main-fixed.dll')


run_tests()

