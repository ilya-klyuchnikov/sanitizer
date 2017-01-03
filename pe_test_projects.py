import subprocess
import shutil

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
LINK_EXE = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\bin\\amd64\\link.exe"

VERBOSE = False
TEST = True


def verbose(msg):
    if VERBOSE:
        print msg


def make_project(files, output_file):
    command = [CL_EXE] + files + INCLUDE_FLAGS + ['/Fe:{0}'.format(output_file), '/link'] + LIBPATH_FLAGS

    print command
    result = subprocess.call(command)
    assert result == 0


def test():
    shutil.rmtree('tmp_projects', ignore_errors=True)
    import os
    os.makedirs('tmp_projects')

    files = [
        'testdata-projects/01-main/lib.c',
        'testdata-projects/01-main/main.c',
    ]

    make_project(files, 'tmp_projects/01-main.exe')


# the main stuff
test()
