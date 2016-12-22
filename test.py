import coff
import subprocess
import os
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
LIB_EXE = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\bin\\amd64\\lib.exe"
LINK_EXE = "C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC\\bin\\amd64\\link.exe"


def build_obj(project):
    flags = [
        '/c',
        # '/Zi',  # place info into debug file
        # '/Fd:tmp/{0}/main.pdb'.format(project),
        '/Fo:tmp/{0}/main.obj'.format(project),
        'testdata/{0}/main.c'.format(project),
    ]
    command = [CL_EXE] + INCLUDE_FLAGS + flags
    print command
    result = subprocess.call(command)
    assert result == 0


def link_exe(project):
    flags = ['tmp/{0}/main.obj'.format(project), '/OUT:tmp/{0}/main.exe'.format(project)]
    command = [LINK_EXE] + LIBPATH_FLAGS + flags
    print command
    result = subprocess.call(command)
    assert result == 0


def link_dll(project):
    flags = ['tmp/{0}/main.obj'.format(project), '/DLL', '/OUT:tmp/{0}/main.dll'.format(project)]
    command = [LINK_EXE] + LIBPATH_FLAGS + flags
    print command
    result = subprocess.call(command)
    assert result == 0


def make_lib(project):
    flags = ['main.obj'.format(project), '/OUT:main.lib'.format(project)]
    command = [LIB_EXE] + flags
    print command
    result = subprocess.call(command, cwd='tmp/{0}'.format(project))
    assert result == 0


def compare_files(f1, f2):
    with open(f1, 'rb') as file1, open(f2, 'rb') as file2:
        return file1.read() == file2.read()

shutil.rmtree('tmp', ignore_errors=True)
os.mkdir('tmp')
os.mkdir('tmp/p1')
os.mkdir('tmp/p2')

build_obj('p1')
build_obj('p2')

link_exe('p1')
link_exe('p2')

link_dll('p1')
link_dll('p2')

make_lib('p1')
make_lib('p2')

print compare_files('tmp/p1/main.obj', 'tmp/p2/main.obj')
print compare_files('tmp/p1/main.exe', 'tmp/p2/main.exe')
print compare_files('tmp/p1/main.dll', 'tmp/p2/main.dll')
print compare_files('tmp/p1/main.lib', 'tmp/p2/main.lib')

coff.strip('tmp/p1/main.obj', 'tmp/p1/main-stripped.obj')
coff.strip('tmp/p2/main.obj', 'tmp/p2/main-stripped.obj')

print compare_files('tmp/p1/main-stripped.obj', 'tmp/p2/main-stripped.obj')
print compare_files('tmp/p1/main-stripped.obj', 'testdata/main-stripped.obj')
