# Experimental utilities to make cxx compilation with MSVS compilers deterministic

* `obj.strip(input_file, out_file)` - strips an `obj` file produced by a MSVC compiler removing/modifying following information:
  * removes `IMAGE_SCN_MEM_DISCARDABLE` sections which do not have `IMAGE_SCN_LNK_COMDAT` attribute
    (usually, they are `debug$s` and `debug$t` sections).
  * sets timestamps to `0`
* `lib.fix_lib_timestamps(input_file, out_file)` - sets all timestamps of a `lib` file (produced by `lib.exe`) to `0`.
* `pefile.default_timestamp()` - a hack in `pefile` - sets all timestamps of a pe file to 0.

See `obj_test.py` and `pe_test.py` for examples.

* `obj_test.py` - checks that after sanitizing `*.obj` files are similar byte-by-byte.
* `lib_test.py` - checks `lib.fix_lib_timestamps`
* `pe_test_projects.py` - creates `*.dll` and `*.exe` files from sanitized object files, fixes all timestamps of the
  created files (using `pefile` library), checks that fixed files are the same byte-by-byte.

