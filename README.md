# Utilities to make cxx compilation with MSVS compilers more deterministic

## coff.py

Description: removes information with absolute paths from object files (in COFF format).

Usage: `python coff.py input.obj output.obj`.

## Subtleties

Some details may depend not only on a name of a dir of a project in filesystem, but also on a length of a path.

## TODO

- more tests for different directories (long/short paths) and different options
- describe assertions
- store exceptions
