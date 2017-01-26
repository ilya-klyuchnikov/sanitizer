# Experimental utilities to make cxx compilation with MSVS compilers deterministic and hermetic

## The problem

VS tools (`cl.exe`, `link.exe`, `lib.exe`) are not deterministic. Given exactly the same sources, they do not produce
the same (byte-for-byte) outputs.

**Why?** 

- They put so called compilation timestamp into any possible piece of output.
- They put absolute pats to files into output.
- For debug builds GUIDs are put into binaries (dll, exe) and debug symbols (pdb files) to be able to match them.

## The scope of current solution

Sanitizer is able to make release builds byte-for-byte deterministic.

**What are release builds?**

- Compilation happens without storing debug information (no `/Zi`, `/ZI` or `/Z7` compiler's flag)
- Linking wihout pdb files

**How?**

- Fixing compilation timestamps to a default or a predifined deterministic value.
- Removing the redundant `debug$s` (for release builds) section from object files.

## Usage

- `python release_normalize --input-object=foo.obj --output-object=foo.normalized.obj` - normalizes an object file
- `python release_normalize --input-lib=foo.lib --output-image=foo.normalized.lib` - normalizes a lib file
- `python release_normalize --input-image=foo.dll --output-image=foo.normalized.dll` - normalizes an image (dll/exe) file
