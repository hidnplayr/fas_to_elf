# fas_to_elf_dbg — FASM debug symbol converter

Converts a FASM `.fas` symbolic information file into a minimal ELF object that
GDB can load with `add-symbol-file`, giving you named breakpoints, struct field
offsets, and source-level stepping for any binary assembled with FASM.

---

## Quick start

```bash
# Assemble with debug symbols dump to file
fasm kernel.asm kernel.bin -s kernel.fas

# Convert the .fas to .elf
python3 fas_to_elf_dbg.py kernel.fas -o kernel_dbg.elf

# In GDB (remote or local)
(gdb) add-symbol-file kernel_dbg.elf 0
(gdb) b osloop
(gdb) b kernel.asm:1154
(gdb) layout src
```

The `0` in `add-symbol-file kernel_dbg.elf 0` tells GDB to apply zero relocation
offset. All symbol values in the ELF carry their final virtual addresses exactly
as FASM computed them, so no offset is needed for `format binary` binaries.

---

## Options

| Flag | Default | Description |
|---|---|---|
| `-o FILE` | `<input>_dbg.elf` | Output ELF path |
| `--rebase HEX` | `0` | Add a constant offset to every address. Use when the load address differs from the `org` value in the source. |
| `-v` | off | Verbose: print every parsed symbol and source file to stderr |

---

## What the output ELF contains

| Section | Contents |
|---|---|
| `.text` / `.data` / … | One placeholder section per FASM output section (1 byte each). GDB uses these as the section index for each symbol; actual bytes are read from the target. |
| `.symtab` / `.strtab` | Every defined, non-variable, non-marker label from the FAS symbols table. |
| `.debug_abbrev` | DWARF-2 abbreviation table (required by `.debug_info`). |
| `.debug_info` | Single compile-unit DIE with `DW_AT_stmt_list` linking to the line table and `DW_AT_low_pc/high_pc` covering the full address range. |
| `.debug_line` | DWARF-2 line-number program mapping every assembled address back to its source file and line. |

---

## Symbol classification

FASM records a `val_type` field for every symbol:

| `val_type` | Meaning | ELF section index |
|---|---|---|
| `0` (absolute) | Compile-time constant or struct field offset | `SHN_ABS` |
| `0` (absolute) + address appears in assembly dump | Real code/data label in `format binary` | `.text` |
| non-zero (relocatable 32/64-bit) | Runtime virtual address | Corresponding output section |
| non-zero + field+20 high bit set | External symbol (`extrn`) | `SHN_UNDEF` |

For `format binary` output, FASM marks every label `val_type=0` because addresses
are baked in directly. The converter disambiguates real labels from constants by
cross-referencing against the assembly dump: if FASM emitted a dump row at that
address, it is a real label; otherwise it is a constant or struct offset.

Names containing `?` are FASM-internal auto-generated identifiers (anonymous
struct bases, proc-macro argument slots, import table entries) and are excluded
from the output.

---

## Supported output formats

| FASM format | Section detection | Symbols |
|---|---|---|
| `format binary` | Addr-decrease in dump (org regions) | All `val_type=0`; real labels found via dump-address set |
| `format ELF` / `format COFF` | Field +20 in dump rows (spec-defined section index) | `val_type` distinguishes code from ABS |
| `format PE` | Addr-decrease (single section) | Same as binary |
| `format MZ` | Addr-decrease | Same as binary |

---

## Source file paths

FASM records source file names in the preprocessed source blob as offsets relative
to the main input file's directory. The converter passes these relative paths
directly into the DWARF file name table with `dir_index=0`, which instructs GDB to
resolve them relative to `DW_AT_comp_dir` — the directory containing the `.fas`
file. As long as the source tree sits beside the `.fas` file (which is always true
when FASM is run in-tree), GDB will find every included file automatically.

---

## Kernel with multiple address regions

KolibriOS (and similar kernels) mix physical boot-code addresses (`0x0`–`0x1ffff`)
with virtual kernel addresses (`0x80000000+`) in a single `format binary` image.
The converter handles this by:

1. Detecting section boundaries via the addr-decrease heuristic and emitting a
   separate DWARF address sequence for each region.
2. Computing `DW_AT_low_pc/high_pc` from the actual min/max of all assembled
   addresses, so the compile unit covers the full range (from `0x0` through
   the top of the kernel) and GDB can resolve source lines anywhere.
3. Using the dump-address set for label classification, so boot-code labels like
   `B32` (physical `0x11aa0`) are correctly placed in `.text` rather than `SHN_ABS`.

---

## Spec reference

The `.fas` file format is documented in
[FAS.TXT](https://github.com/tgrysztar/fasm/blob/master/TOOLS/FAS.TXT)
in the official FASM repository.

Key structures used:

- **Table 1** — file header, locating all sub-tables
- **Table 2** — symbol records (value, flags, val_type, field+20 for section/external)
- **Table 3** — preprocessed source lines (filename, line number, macro flag)
- **Table 4** — assembly dump rows (output file offset, virtual address, section info)
- **Header +48/+52** — section names table (ELF/COFF only)
