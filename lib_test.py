import coff
import subprocess
import shutil
import sys

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


def make_lib(projects, files, output):
    """builds 2 lib files"""
    for project in projects:
        flags = [
            '/nologo',
            '/OUT:{0}'.format(output)
        ] + files
        command = [LIB_EXE] + flags
        verbose(command)
        result = subprocess.call(command, cwd=project)
        assert result == 0


def strip(projects, name):
    """builds 2 lib files"""
    for project in projects:
        coff.strip('{0}/{1}.obj'.format(project, name), '{0}/{1}-stripped.obj'.format(project, name))

def build():
    FLAGS = [
        [],
        # ['/Zi'],
        # ['/ZI'],
        # ['/Z7'],
        # ['/Gm', '/Zi'],
        # ['/Gm', '/ZI'],
        # # wrong assumption about headers
        # # ['/GL'],
        # ['/GR'],
        # ['/Gw'],
        # ['/Gy'],
        # ['/X'],
        # ['/O1'],
        # ['/O2'],
        # ['/Od'],
        # ['/Oi'],
        # ['/Os'],
        # ['/Ot'],
    ]

    files = [
        ('util1', 'c'),
        ('util2', 'cpp'),
        ('util3', 'cpp'),
    ]

    shutil.rmtree('tmp_lib', ignore_errors=True)
    # import os
    #os.makedirs('testdata/expected')

    for i in range(0, len(FLAGS)):
        flags = FLAGS[i]
        print '================== {0},  =================='.format(flags)

        projects = [
            'tmp-lib/{0}/1'.format(i),
            'tmp-lib/{0}/long_dir/long_dir/long_dir/long_dir/long_dir/long_dir/long_dir/long_dir/long_dir'.format(i),
        ]

        shutil.copytree('testdata-lib/src', projects[0])
        shutil.copytree('testdata-lib/src', projects[1])

        for f, ext in files:
            print 'FILE: {0}.{1}, OPTIONS: {2}'.format(f, ext, flags)
            sys.stdout.flush()
            build_obj(projects, f, ext, flags)
            strip(projects, f)

        obj_files = map(lambda x: x[0] + '.obj', files)
        obj_files_stripped = map(lambda x: x[0] + '-stripped.obj', files)

        make_lib(projects, obj_files, 'lib.lib')
        make_lib(projects, obj_files_stripped, 'lib-stripped.lib')


# the main stuff
build()
