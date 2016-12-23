import coff
import subprocess
import shutil
import os

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

FLAGS = [
    [],
    ['/Zi']
]

VERBOSE = False
TEST = True


def verbose(msg):
    if VERBOSE:
        print msg


def build_obj(projects, name, extension, extra_flags):
    """builds 2 obj files"""
    for project in projects:
        flags = [
            '/nologo',
            '/c',
            # '/Fd:tmp/{0}/main.pdb'.format(project),
            '/Fo:{0}/{1}.obj'.format(project, name),
            '{0}/{1}.{2}'.format(project, name, extension),
        ]
        command = [CL_EXE] + INCLUDE_FLAGS + flags + extra_flags
        verbose(command)
        result = subprocess.call(command)
        assert result == 0


# not everything could be a dll - so, maybe skip this part?
def link_exe(projects, name):
    """builds 2 exe files"""
    for project in projects:
        flags = [
            '/nologo',
            '{0}/{1}.obj'.format(project, name),
            '/OUT:{0}/{1}.exe'.format(project, name),
        ]
        command = [LINK_EXE] + LIBPATH_FLAGS + flags
        verbose(command)
        result = subprocess.call(command)
        assert result == 0


def link_dll(projects, name):
    """builds 2 dll files"""
    for project in projects:
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


def make_lib(projects, name):
    """builds 2 lib files"""
    for project in projects:
        flags = [
            '/nologo',
            '{0}.obj'.format(name),
            '/OUT:{0}.lib'.format(name)
        ]
        command = [LIB_EXE] + flags
        verbose(command)
        result = subprocess.call(command, cwd=project)
        assert result == 0


def strip(projects, name):
    """builds 2 lib files"""
    for project in projects:
        coff.strip('{0}/{1}.obj'.format(project, name), '{0}/{1}-stripped.obj'.format(project, name))


def compare_files(f1, f2):
    with open(f1, 'rb') as file1, open(f2, 'rb') as file2:
        return file1.read() == file2.read()


def check_diff(projects, name):
    n1 = '{0}/{1}.obj'.format(projects[0], name)
    n2 = '{0}/{1}.obj'.format(projects[1], name)
    assert not compare_files(n1, n2), name


def check_the_same(projects, name):
    n1 = '{0}/{1}-stripped.obj'.format(projects[0], name)
    n2 = '{0}/{1}-stripped.obj'.format(projects[1], name)
    assert compare_files(n1, n2)


def check_expected(i, projects, name):
    n1 = '{0}/{1}-stripped.obj'.format(projects[0], name)
    n2 = 'testdata/expected/{0}_{1}-stripped.obj'.format(i, name)
    the_same = compare_files(n1, n2)
    if TEST:
        assert the_same, name
    elif not the_same:
        print 'FAILURE: {0}, {1}'.format(i, name)


def copy_expected(i, projects, name):
    n1 = '{0}/{1}-stripped.obj'.format(projects[0], name)
    n2 = 'testdata/expected/{0}_{1}-stripped.obj'.format(i, name)
    shutil.copyfile(n1, n2)


def build():



    files = [
        ('main', 'c'),
        ('main1', 'cpp'),
        ('test', 'cpp'),
    ]

    shutil.rmtree('tmp', ignore_errors=True)
    #os.makedirs('testdata/expected')

    for i in range(0, len(FLAGS)):
        flags = FLAGS[i]

        projects = [
            'tmp/{0}/p1'.format(i),
            'tmp/{0}/p2'.format(i),
        ]

        shutil.copytree('testdata/src', projects[0])
        shutil.copytree('testdata/src', projects[1])

        for f, ext in files:
            build_obj(projects, f, ext, flags)
            link_dll(projects, f)
            make_lib(projects, f)
            strip(projects, f)
            check_diff(projects, f)
            check_the_same(projects, f)
            link_dll(projects, f + '-stripped')
            check_expected(i, projects, f)
            #copy_expected(i, projects, f)

# the main stuff
build()
