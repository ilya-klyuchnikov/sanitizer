# https://msdn.microsoft.com/en-us/library/ba1z7822.aspx#Example
# https://msdn.microsoft.com/en-us/library/2kzt1wy3(v=vs.80).aspx - very interesting

import subprocess
import shutil
import time
import pefile

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


def build_obj_files(project_dir, input_files, pdb_file):
    flags = [
        '/nologo',
        '/c',
        '/Zi',
        '/Fd{0}'.format(pdb_file),
    ]
    command = [CL_EXE] + INCLUDE_FLAGS + flags + input_files
    verbose(command)
    result = subprocess.call(command, cwd=project_dir)
    assert result == 0


def link_dll(project_dir, obj_files, output_file, pdb_file):
    command = [LINK_EXE, '/INCREMENTAL:NO', '/dll'] + LIBPATH_FLAGS + obj_files + ['/out:{0}'.format(output_file), '/pdb:{0}'.format(pdb_file), '/debug:fastlink']
    verbose(command)
    result = subprocess.call(command, cwd=project_dir)
    assert result == 0


def compare_files(f1, f2):
    with open(f1, 'rb') as file1, open(f2, 'rb') as file2:
        return file1.read() == file2.read()


def run_tests():

    shutil.rmtree('tmp_pdb_0')
    shutil.copytree('testdata', 'tmp_pdb_0')

    build_obj_files(
        'tmp_pdb_0',
        ['foo.c', 'bar.c'],
        'obj_pdb.pdb'
    )

    link_dll(
        'tmp_pdb_0',
        ['foo.obj', 'bar.obj'],
        'dll.dll',
        'dll_pdb.pdb'
    )

    pe = pefile.PE('tmp_pdb_0/dll.dll')
    pe.default_timestamp()
    pe.write('tmp_pdb_0/dll-fixed.dll')
    pe.close()

run_tests()

time.sleep(5)
shutil.rmtree('tmp_pdb_1')
shutil.copytree('tmp_pdb_0', 'tmp_pdb_1')

run_tests()
