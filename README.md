# Utilities to make cxx compilation with MSVS compilers more deterministic

## coff.py

Description: removes information with absolute paths from object files (in COFF format).

Usage: `python coff.py input.obj output.obj`.

## Subtleties

`coff.py` for now doesn't work with any options across different machines (eg. it doesn't work with `/Zi` option).

TODO: investigate a set of options for which `coff.py` works across different machines.