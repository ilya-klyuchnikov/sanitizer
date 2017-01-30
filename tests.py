import obj
import subprocess
import shutil
import sys
import json
import os
import pipes
import pefile

# this is x64 version. TODO - make 32 bin version as well
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


TESTS = [
    "testdata/01"
]


def execute_step(test_dir, step):
    if "compile" in step:
        compile(test_dir, step["compile"]["flags"])
    elif "fix_obj" in step:
        fix_obj(test_dir, step["fix_obj"]["input"], step["fix_obj"]["output"])
    elif "link" in step:
        link(test_dir, step["link"]["flags"])
    elif "fix_pe" in step:
        fix_pe(test_dir, step["fix_pe"]["input"], step["fix_pe"]["output"])
    elif "compare" in step:
        compare(test_dir, step["compare"]["file1"], step["compare"]["file2"])
    else:
        raise Exception("cannot parse {0}".format(step))


def compile(test_dir, flags):
    command = [CL_EXE] + flags + INCLUDE_FLAGS
    print(" ".join(map(pipes.quote, command)))
    result = subprocess.call(command, cwd=test_dir)
    assert result == 0


def fix_obj(test_dir, input, output):
    input_file = "{0}/{1}".format(test_dir, input)
    output_file = "{0}/{1}".format(test_dir, output)
    print("fix_obj {0} --> {1}".format(input_file, output_file))
    obj.strip(input_file, output_file)


def fix_pe(test_dir, input, output):
    input_file = "{0}/{1}".format(test_dir, input)
    output_file = "{0}/{1}".format(test_dir, output)
    print("fix_pe {0} --> {1}".format(input_file, output_file))
    pe = pefile.PE(input_file)
    pe.default_timestamp()
    pe.write(output_file)
    pe.close()


def link(test_dir, flags):
    command = [LINK_EXE] + flags + LIBPATH_FLAGS
    print(" ".join(map(pipes.quote, command)))
    result = subprocess.call(command, cwd=test_dir)
    assert result == 0


def compare(test_dir, f1, f2):
    input_f1 = "{0}/{1}".format(test_dir, f1)
    input_f2 = "{0}/{1}".format(test_dir, f2)
    print("{0} <==> {1}".format(input_f1, input_f2))
    with open(input_f1, 'rb') as file1, open(input_f2, 'rb') as file2:
        assert file1.read() == file2.read()


def exec_test(t):
    input_dir = t
    input_file = "{0}/{1}".format(t, "test.json")
    with open(input_file) as input:
        config = json.load(input)
        print config

    test_dir = "{0}/{1}".format("tmp", config['test_dir'])
    print test_dir

    shutil.copytree(input_dir, test_dir)
    steps = config['steps']
    for step in steps:
        execute_step(test_dir, step)


if os.path.isdir("tmp"):
    shutil.rmtree("tmp")
os.makedirs("tmp")

for t in TESTS:
    exec_test(t)