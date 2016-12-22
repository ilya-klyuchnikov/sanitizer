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

PROJECTS = ['tmp/p1', 'tmp/p2']

VERBOSE = False


def verbose(msg):
    if VERBOSE:
        print msg


def build_obj(name, extension):
    """builds 2 obj files"""
    for project in PROJECTS:
        flags = [
            '/nologo',
            '/c',
            # '/Fd:tmp/{0}/main.pdb'.format(project),
            '/Fo:{0}/{1}.obj'.format(project, name),
            '{0}/{1}.{2}'.format(project, name, extension),
        ]
        command = [CL_EXE] + INCLUDE_FLAGS + flags
        verbose(command)
        result = subprocess.call(command)
        assert result == 0


# not everything could be a dll - so, maybe skip this part?
def link_exe(name):
    """builds 2 exe files"""
    for project in PROJECTS:
        flags = [
            '/nologo',
            '{0}/{1}.obj'.format(project, name),
            '/OUT:{0}/{1}.exe'.format(project, name),
        ]
        command = [LINK_EXE] + LIBPATH_FLAGS + flags
        verbose(command)
        result = subprocess.call(command)
        assert result == 0


def link_dll(name):
    """builds 2 dll files"""
    for project in PROJECTS:
        flags = [
            '/nologo',
            '{0}/{1}.obj'.format(project, name),
            '/DLL',
            '/OUT:{0}/{1}.dll'.format(project, name),
        ]
        command = [LINK_EXE] + LIBPATH_FLAGS + flags
        verbose(command)
        result = subprocess.call(command)
        assert result == 0


def make_lib(name):
    """builds 2 lib files"""
    for project in PROJECTS:
        flags = [
            '/nologo',
            '{0}.obj'.format(name),
            '/OUT:{0}.lib'.format(name)
        ]
        command = [LIB_EXE] + flags
        verbose(command)
        result = subprocess.call(command, cwd=project)
        assert result == 0


def strip(name):
    """builds 2 lib files"""
    for project in PROJECTS:
        coff.strip('{0}/{1}.obj'.format(project, name), '{0}/{1}-stripped.obj'.format(project, name))


def compare_files(f1, f2):
    with open(f1, 'rb') as file1, open(f2, 'rb') as file2:
        return file1.read() == file2.read()


def check_diff(name):
    n1 = '{0}/{1}.obj'.format(PROJECTS[0], name)
    n2 = '{0}/{1}.obj'.format(PROJECTS[1], name)
    assert not compare_files(n1, n2), name


def check_the_same(name):
    n1 = '{0}/{1}-stripped.obj'.format(PROJECTS[0], name)
    n2 = '{0}/{1}-stripped.obj'.format(PROJECTS[1], name)
    assert compare_files(n1, n2)


def check_expected(name):
    n1 = '{0}/{1}-stripped.obj'.format(PROJECTS[0], name)
    n2 = '{0}/{1}-stripped.obj'.format('testdata/expected', name)
    assert compare_files(n1, n2), name


def copy_expected(name):
    n1 = '{0}/{1}-stripped.obj'.format(PROJECTS[0], name)
    n2 = '{0}/{1}-stripped.obj'.format('testdata/expected', name)
    shutil.copyfile(n1, n2)

shutil.rmtree('tmp', ignore_errors=True)
shutil.copytree('testdata/src', 'tmp/p1')
shutil.copytree('testdata/src', 'tmp/p2')

files = [
    ('main', 'c'),
    ('main1', 'cpp'),
    ('test', 'cpp'),
]

for f, ext in files:
    build_obj(f, ext)
    link_dll(f)
    make_lib(f)
    strip(f)
    check_diff(f)
    check_the_same(f)
    link_dll(f + '-stripped')
    check_expected(f)
    #copy_expected(f)
