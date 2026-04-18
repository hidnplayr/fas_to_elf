#!/usr/bin/env python3
"""
fas_to_elf_dbg.py - Convert a FASM .fas file into a minimal ELF debug object.

The output ELF contains:
  - SHT_SYMTAB   : every defined, non-variable, non-marker label
  - SHT_STRTAB   : symbol name strings
  - .debug_abbrev: DWARF-2 abbreviation table (required by .debug_info)
  - .debug_info  : DWARF-2 compile-unit DIE (makes GDB recognise DWARF)
  - .debug_line  : DWARF-2 line-number program (address <-> source line mapping)
  - .debug_str   : filename strings referenced by the compile unit

GDB usage:
    (gdb) add-symbol-file kernel_dbg.elf 0   # .text sh_addr=0, symbols carry absolute VAs
    (gdb) info functions                      # all FASM labels
    (gdb) b kernel_start                      # break by name
    (gdb) b kernel.asm:42                     # break by source line
    (gdb) layout src                          # source view while stepping

Based on the official FAS.TXT spec:
    https://github.com/tgrysztar/fasm/blob/master/TOOLS/FAS.TXT

Usage:
    python3 fas_to_elf_dbg.py kernel.fas [-o kernel_dbg.elf] [--rebase 0xNNNN]

    --rebase  : add a constant to every address (use when load VA != org value)
    -o        : output path (default: <input>_dbg.elf)
    -v        : verbose: print every symbol and line entry to stderr

Changes vs original:
  [FIX 1] Added .debug_abbrev + .debug_info with a DW_TAG_compile_unit DIE.
          Without .debug_info GDB prints "No debugging symbols found" and
          source-level commands (b file:line, layout src) do not work at all,
          even when .debug_line is present.
  [FIX 2] Symbol shndx now uses val_type from the FAS record:
          val_type == 0  →  SHN_ABS  (absolute constant / struct offset)
          val_type != 0  →  shndx = .text  (runtime virtual address)
          Previously every symbol was forced into .text, which caused the
          534 struct-offset labels (TSS._back, MUTEX.wait_list, …) to appear
          as functions at address 0x00000000 in "info functions".
  [FIX 3] Absolute symbols use STT_OBJECT; code labels use STT_NOTYPE so that
          GDB does not misclassify every address-0 offset as a function.
"""

import argparse
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# FAS format constants
# ---------------------------------------------------------------------------
FAS_SIGNATURE   = 0x1A736166   # little-endian dword at offset 0

# Symbol flags (Table 2.1)
SYM_DEFINED     = 0x0001
SYM_VARIABLE    = 0x0002
SYM_MARKER      = 0x0400

# val_type (byte at symbol record +11)
VTYPE_ABSOLUTE  = 0   # compile-time constant / struct offset — no relocation
# any non-zero value means the symbol carries a runtime virtual address

# Assembly dump flags (Table 4, offset +26)
DUMP_VIRTUAL    = 0x01   # inside 'virtual' block — no real output offset
DUMP_NOINFILE   = 0x02   # reserved data / not in output file

# Preprocessed line: high bit of dword at +4
PREP_MACRO_BIT  = 0x80000000

# ---------------------------------------------------------------------------
# ELF constants (32-bit little-endian)
# ---------------------------------------------------------------------------
ELFMAG          = b'\x7fELF'
ELFCLASS32      = 1
ELFDATA2LSB     = 1
ET_EXEC         = 2
EM_386          = 3

SHT_NULL        = 0
SHT_PROGBITS    = 1
SHT_SYMTAB      = 2
SHT_STRTAB      = 3
SHF_NONE        = 0
SHN_ABS         = 0xFFF1   # absolute symbol — not relative to any section

STB_LOCAL       = 0
STB_GLOBAL      = 1
STT_NOTYPE      = 0
STT_OBJECT      = 1
STT_FUNC        = 2
STV_DEFAULT     = 0

# DWARF-2 tags / attributes / forms / opcodes
DW_TAG_compile_unit     = 0x11
DW_AT_name              = 0x03
DW_AT_language          = 0x13
DW_AT_comp_dir          = 0x1b
DW_AT_stmt_list         = 0x10   # offset into .debug_line
DW_AT_low_pc            = 0x11
DW_AT_high_pc           = 0x12
DW_FORM_string          = 0x08   # inline NUL-terminated string
DW_FORM_data4           = 0x06   # 4-byte constant
DW_FORM_addr            = 0x01   # address-sized (4 bytes for 32-bit)
DW_LANG_Mips_Assembler  = 0x8001 # closest standard language for asm

DW_LNS_copy             = 1
DW_LNS_advance_pc       = 2
DW_LNS_advance_line     = 3
DW_LNS_set_file         = 4
DW_LNS_set_column       = 5
DW_LNS_negate_stmt      = 6
DW_LNE_end_sequence     = 1
DW_LNE_set_address      = 2


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class FasHeader:
    ver_major:        int
    ver_minor:        int
    header_len:       int
    input_name_off:   int   # offset within strings table
    output_name_off:  int
    strings_off:      int
    strings_len:      int
    symbols_off:      int
    symbols_len:      int
    source_off:       int
    source_len:       int
    dump_off:         int
    dump_len:         int   # 0 means no assembly dump (error during assembly)
    sec_names_off:    int   # offset of section names table (ELF/COFF only)
    sec_names_len:    int   # length; 0 for format binary/PE/MZ

@dataclass
class FasSymbol:
    value:      int
    flags:      int
    data_size:  int   # 0 = plain label, >0 = bytes labelled
    val_type:   int   # 0=absolute (struct offset/const), non-zero=virtual address
    name_ref:   int   # high bit set → strings table (NUL), clear → preproc source (pascal)
    source_line_off: int  # offset of defining line in preprocessed source
    field20:         int = 0  # raw symbol +20 field (section/external info per spec Table 2)
    # resolved later:
    name:          str  = ''
    section_index: int  = 0    # which output section this symbol belongs to (0-based)
    is_external:   bool = False # True when field20 high bit set -> external ref -> SHN_UNDEF

@dataclass
class PrepLine:
    """Decoded preprocessed source line header (Table 3)."""
    offset:      int   # byte offset of this record within the preprocessed source blob
    file_or_macro_off: int   # +0
    line_info:   int         # +4  (high bit = macro-generated, bits 0-30 = line number)
    position:    int         # +8
    macro_line:  int         # +12
    # resolved:
    is_macro:    bool  = False
    line_number: int   = 0
    filename:    str   = ''  # original source filename (empty for main file)

@dataclass
class DumpRow:
    """Decoded assembly dump row (Table 4)."""
    file_offset:   int    # offset in output binary
    source_off:    int    # offset of line in preprocessed source
    addr:          int    # value of $ (virtual address)
    flags:         int    # +26 byte
    code_type:     int    # 16, 32, or 64
    section_index: int  = 0  # which output section this row belongs to
    # resolved later:
    line:          Optional[PrepLine] = None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
class FasParser:
    def __init__(self, data: bytes, rebase: int = 0, verbose: bool = False):
        self.data    = data
        self.rebase  = rebase
        self.verbose = verbose
        self.hdr:    FasHeader
        self.symbols:       list[FasSymbol] = []
        self.dump:          list[DumpRow]   = []
        self.n_sections:    int = 1
        # Set of all $ addresses that appear in dump rows (non-virtual, non-noinfile).
        # Used in binary-format mode to classify vtype=0 labels: a symbol whose
        # value matches a dump address is a real code/data label; one that doesn't
        # is a compile-time constant or struct field offset.
        self.dump_addr_set: set[int] = set()
        # Section names from the section names table (ELF/COFF only).
        # section_names[i] = name of FAS section i+1 (table is 1-based).
        self.section_names: list[str] = []
        # map: prep-source-offset -> PrepLine
        self._prep_lines: dict[int, PrepLine] = {}
        # cache: filename strings
        self._main_filename = ''

    # ------------------------------------------------------------------
    def parse(self):
        self._parse_header()
        self._parse_section_names()  # ELF/COFF only; empty list for other formats
        self._index_prep_lines()
        self._parse_dump()
        self._parse_symbols()

    # ------------------------------------------------------------------
    def _u8(self, off):  return self.data[off]
    def _u16(self, off): return struct.unpack_from('<H', self.data, off)[0]
    def _u32(self, off): return struct.unpack_from('<I', self.data, off)[0]
    def _u64(self, off): return struct.unpack_from('<Q', self.data, off)[0]

    def _null_str(self, off) -> str:
        end = self.data.index(b'\x00', off)
        return self.data[off:end].decode('ascii', errors='replace')

    def _pascal_str(self, off) -> str:
        length = self.data[off]
        return self.data[off+1 : off+1+length].decode('ascii', errors='replace')

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    def _parse_section_names(self):
        """
        Parse the section names table (header +48/+52).
        Per spec: exists only for ELF/COFF output.  Each entry is a
        4-byte offset into the strings table giving the section name.
        The index in this table matches the section index in the output
        file (1-based: entry 0 here = section 1 in FASM).
        """
        h = self.hdr
        if h.sec_names_len == 0:
            return
        n = h.sec_names_len // 4
        for i in range(n):
            name_off = self._u32(h.sec_names_off + i * 4)
            name = self._null_str(h.strings_off + name_off)
            self.section_names.append(name)
        if self.verbose:
            for i, name in enumerate(self.section_names, 1):
                print(f'[fas] section[{i}]: {name!r}', file=sys.stderr)

    # ------------------------------------------------------------------
    def _parse_header(self):
        d = self.data
        if len(d) < 8:
            raise ValueError("File too short to be a .fas file")
        sig = self._u32(0)
        if sig != FAS_SIGNATURE:
            raise ValueError(f"Bad signature {sig:#010x} — not a FASM .fas file")

        hlen = self._u16(6)

        def _opt32(off, default=0):
            return self._u32(off) if hlen > off else default

        self.hdr = FasHeader(
            ver_major       = d[4],
            ver_minor       = d[5],
            header_len      = hlen,
            input_name_off  = _opt32(8),
            output_name_off = _opt32(12),
            strings_off     = _opt32(16),
            strings_len     = _opt32(20),
            symbols_off     = _opt32(24),
            symbols_len     = _opt32(28),
            source_off      = _opt32(32),
            source_len      = _opt32(36),
            dump_off        = _opt32(40),
            dump_len        = _opt32(44),
            # Table 1 +48/+52: section names table (ELF/COFF only; 0 otherwise)
            sec_names_off   = _opt32(48),
            sec_names_len   = _opt32(52),
        )
        h = self.hdr
        if self.verbose:
            print(f"[fas] FASM {h.ver_major}.{h.ver_minor}, header={h.header_len}b", file=sys.stderr)
            print(f"[fas] strings  @ {h.strings_off:#x}  len={h.strings_len:#x}", file=sys.stderr)
            print(f"[fas] symbols  @ {h.symbols_off:#x}  len={h.symbols_len:#x}", file=sys.stderr)
            print(f"[fas] source   @ {h.source_off:#x}  len={h.source_len:#x}", file=sys.stderr)
            print(f"[fas] dump     @ {h.dump_off:#x}  len={h.dump_len:#x}", file=sys.stderr)

        # Resolve main input filename
        if h.strings_len > 0 and h.header_len >= 12:
            self._main_filename = self._null_str(h.strings_off + h.input_name_off)
            if self.verbose:
                print(f"[fas] input file: {self._main_filename}", file=sys.stderr)

    # ------------------------------------------------------------------
    def _resolve_filename_for_prep_line(self, file_off: int, is_macro: bool) -> str:
        if is_macro:
            return self._main_filename
        if file_off == 0:
            return self._main_filename
        try:
            return self._null_str(self.hdr.source_off + file_off)
        except (ValueError, IndexError):
            return self._main_filename

    # ------------------------------------------------------------------
    def _index_prep_lines(self):
        h = self.hdr
        if h.source_len == 0:
            return

        blob_start = h.source_off
        blob_end   = blob_start + h.source_len
        pos        = blob_start

        while pos < blob_end:
            rec_offset = pos - blob_start

            if pos + 16 > blob_end:
                break

            file_off  = self._u32(pos + 0)
            line_info = self._u32(pos + 4)
            position  = self._u32(pos + 8)
            macro_off = self._u32(pos + 12)

            is_macro    = bool(line_info & PREP_MACRO_BIT)
            line_number = line_info & 0x7FFFFFFF

            filename = self._resolve_filename_for_prep_line(file_off, is_macro)

            pl = PrepLine(
                offset            = rec_offset,
                file_or_macro_off = file_off,
                line_info         = line_info,
                position          = position,
                macro_line        = macro_off,
                is_macro          = is_macro,
                line_number       = line_number,
                filename          = filename,
            )
            self._prep_lines[rec_offset] = pl

            tok_start = pos + 16
            tok_pos   = tok_start
            while tok_pos < blob_end and self.data[tok_pos] != 0x00:
                b = self.data[tok_pos]
                if b == 0x1A or b == 0x3B:
                    if tok_pos + 1 < blob_end:
                        tok_pos += 2 + self.data[tok_pos + 1]
                    else:
                        tok_pos += 1
                elif b == 0x22:
                    if tok_pos + 5 < blob_end:
                        qlen = self._u32(tok_pos + 1)
                        tok_pos += 5 + qlen
                    else:
                        tok_pos += 1
                else:
                    tok_pos += 1

            pos = tok_pos + 1

        if self.verbose:
            print(f"[fas] indexed {len(self._prep_lines)} preprocessed lines", file=sys.stderr)

    # ------------------------------------------------------------------
    def _resolve_symbol_name(self, name_ref: int) -> Optional[str]:
        if name_ref == 0:
            return None
        h = self.hdr
        high_bit = name_ref & 0x80000000
        off      = name_ref & 0x7FFFFFFF
        try:
            if high_bit:
                return self._null_str(h.strings_off + off)
            else:
                return self._pascal_str(h.source_off + off)
        except (ValueError, IndexError):
            return None

    # ------------------------------------------------------------------
    def _parse_symbols(self):
        """
        Parse the symbols table per FAS spec Table 2.

        Field +20 is central to correct symbol classification:
          vtype != 0 AND high bit of field+20 clear  -> relocatable symbol;
            bits 0-30 = 1-based section index (same table as section_names).
          vtype != 0 AND high bit of field+20 set    -> external symbol;
            bits 0-30 = offset of symbol name in strings table.
            Emit as SHN_UNDEF.
          vtype == 0                                 -> absolute value.
            For format ELF/COFF this is reliably a struct offset / constant.
            For format binary (no section names table) we apply a span check
            later in build_symtab to distinguish real labels from constants.

        Names containing '?' are FASM-internal auto-generated identifiers
        (anonymous struct bases, proc macro internals, import labels) and
        are excluded — they produce noise in GDB's 'info functions'.
        """
        h = self.hdr
        if h.symbols_len == 0:
            return
        count = h.symbols_len // 32
        # Build map: FAS 1-based section index -> our 0-based section index,
        # using the same mapping established during _parse_dump.
        # For ELF/COFF we have section_names; for binary we use section_index=0.
        has_sec_names = len(self.section_names) > 0

        for i in range(count):
            base = h.symbols_off + i * 32
            value    = self._u64(base +  0)
            flags    = self._u16(base +  8)
            dsize    = self._u8 (base + 10)
            vtype    = self._u8 (base + 11)
            field20  = self._u32(base + 20)  # section/external ref per Table 2
            name_ref = self._u32(base + 24)
            src_off  = self._u32(base + 28)

            if not (flags & SYM_DEFINED):
                continue
            if flags & SYM_VARIABLE:
                continue
            if flags & SYM_MARKER:
                continue

            name = self._resolve_symbol_name(name_ref)
            if not name:
                continue

            # Filter FASM-internal auto-generated names.  The '?' character
            # cannot appear in user-defined identifiers in FASM source, so
            # any name containing it is a compiler-generated internal label
            # (anonymous struct bases: '..base?B', proc arg slots: '..arg?r',
            # import entries: '_label?01', etc.).
            if '?' in name:
                continue

            # Determine section membership and external status from field+20.
            is_external = False
            sec_idx     = 0
            if vtype != VTYPE_ABSOLUTE:
                if field20 & 0x80000000:
                    # High bit set: external symbol (extrn / import).
                    is_external = True
                elif has_sec_names:
                    # High bit clear, ELF/COFF: bits 0-30 = 1-based section index.
                    fas_sec = field20 & 0x7FFFFFFF
                    # Convert to 0-based.  Section 1 in FAS = index 0 here.
                    sec_idx = max(0, fas_sec - 1)
                # else: format binary — sec_idx stays 0 (only one section)

            sym = FasSymbol(
                value           = value + self.rebase,
                flags           = flags,
                data_size       = dsize,
                val_type        = vtype,
                field20         = field20,
                name_ref        = name_ref,
                source_line_off = src_off,
                name            = name,
                section_index   = sec_idx,
                is_external     = is_external,
            )
            self.symbols.append(sym)
            if self.verbose:
                ext_s = ' [external]' if is_external else ''
                print(f'[sym] {name:40s}  va={sym.value:#010x}'
                      f'  vtype={vtype}  sec={sec_idx}{ext_s}', file=sys.stderr)

        if self.verbose:
            print(f'[fas] {len(self.symbols)} usable symbols', file=sys.stderr)

    # ------------------------------------------------------------------
    def _parse_dump(self):
        h = self.hdr
        if h.dump_len == 0:
            if self.verbose:
                print("[fas] no assembly dump (assembly error?)", file=sys.stderr)
            return

        # Determine section index for each dump row.
        #
        # Per spec Table 4 field +20: when the $ address is relocatable,
        # the high bit is clear and bits 0-30 give the 1-based section index.
        # We convert to 0-based internally.
        #
        # When the section names table is present (ELF/COFF), this gives us
        # exact section membership directly from the spec-defined field.
        #
        # For format binary/PE/MZ the $ address has addr_type=0 (absolute),
        # so field+20 is zero and carries no section info.  In that case we
        # fall back to the addr-decrease heuristic: when the virtual counter
        # resets backwards, FASM has switched to a new output section.
        use_field20 = len(self.section_names) > 0   # ELF/COFF only
        section_index = 0
        prev_addr     = None
        # Map from FAS 1-based section index -> our 0-based section index.
        fas_to_local_sec: dict[int, int] = {}
        next_local_sec = 0

        n_records = (h.dump_len - 4) // 28
        for i in range(n_records):
            base = h.dump_off + i * 28

            file_off   = self._u32(base +  0)
            source_off = self._u32(base +  4)
            addr       = self._u64(base +  8)
            field20    = self._u32(base + 20)
            addr_type  = self._u8 (base + 24)
            code_type  = self._u8 (base + 25)
            dump_flags = self._u8 (base + 26)

            if dump_flags & (DUMP_VIRTUAL | DUMP_NOINFILE):
                continue

            if use_field20 and addr_type != 0 and not (field20 & 0x80000000):
                # Spec-defined section index (1-based).  Map to 0-based.
                fas_sec = field20 & 0x7FFFFFFF
                if fas_sec == 0:
                    # fas_sec=0 is invalid (spec is 1-based); this row is a
                    # preamble directive before any section is established.
                    # Assign to local section 0 without creating a new entry.
                    section_index = 0
                else:
                    # Valid 1-based index: convert to 0-based local index.
                    if fas_sec not in fas_to_local_sec:
                        fas_to_local_sec[fas_sec] = next_local_sec
                        next_local_sec += 1
                    section_index = fas_to_local_sec[fas_sec]
            else:
                # Fallback: addr-decrease heuristic for format binary/PE.
                if prev_addr is not None and addr < prev_addr:
                    section_index += 1

            prev_addr = addr

            pl = self._prep_lines.get(source_off)

            row = DumpRow(
                file_offset   = file_off,
                source_off    = source_off,
                addr          = addr + self.rebase,
                flags         = dump_flags,
                code_type     = code_type,
                section_index = section_index,
                line          = pl,
            )
            self.dump.append(row)
            self.dump_addr_set.add(addr + self.rebase)

        self.n_sections = max((r.section_index for r in self.dump), default=0) + 1

        if self.verbose:
            print(f'[fas] {len(self.dump)} assembly dump rows '
                  f'across {self.n_sections} section(s)', file=sys.stderr)


# ---------------------------------------------------------------------------
# DWARF-2 line number program builder
# ---------------------------------------------------------------------------
class DwarfLineProgram:
    """
    Emits a minimal DWARF-2 .debug_line section covering the address->line
    mapping extracted from the FAS assembly dump.
    """

    STD_OPCODE_LENGTHS = [0,  # opcode 0 (extended — handled separately)
                          0,  # DW_LNS_copy
                          1,  # DW_LNS_advance_pc
                          1,  # DW_LNS_advance_line
                          1,  # DW_LNS_set_file
                          1,  # DW_LNS_set_column
                          0,  # DW_LNS_negate_stmt
                          0,  # DW_LNS_set_basic_block
                          0,  # DW_LNS_const_add_pc
                          1,  # DW_LNS_fixed_advance_pc
                          ]

    def __init__(self):
        self._files: list[str] = []
        self._file_index: dict[str, int] = {}
        self._prog = bytearray()

    # ------------------------------------------------------------------
    def _uleb128(self, v: int) -> bytes:
        out = []
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                out.append(b | 0x80)
            else:
                out.append(b)
                break
        return bytes(out)

    def _sleb128(self, v: int) -> bytes:
        out = []
        more = True
        while more:
            b = v & 0x7F
            v >>= 7
            if (v == 0 and not (b & 0x40)) or (v == -1 and (b & 0x40)):
                more = False
            else:
                b |= 0x80
            out.append(b)
        return bytes(out)

    # ------------------------------------------------------------------
    def register_file(self, filename: str) -> int:
        """Return 1-based file index, registering if new."""
        if filename not in self._file_index:
            idx = len(self._files) + 1
            self._files.append(filename)
            self._file_index[filename] = idx
        return self._file_index[filename]

    # ------------------------------------------------------------------
    def _emit_extended(self, opcode: int, payload: bytes):
        self._prog.append(0x00)
        self._prog += self._uleb128(1 + len(payload))
        self._prog.append(opcode)
        self._prog += payload

    def _emit_set_address(self, addr: int):
        self._emit_extended(DW_LNE_set_address, struct.pack('<I', addr & 0xFFFFFFFF))

    def _emit_end_sequence(self):
        self._emit_extended(DW_LNE_end_sequence, b'')

    def _emit_advance_pc(self, delta: int):
        self._prog.append(DW_LNS_advance_pc)
        self._prog += self._uleb128(delta)

    def _emit_advance_line(self, delta: int):
        self._prog.append(DW_LNS_advance_line)
        self._prog += self._sleb128(delta)

    def _emit_set_file(self, file_idx: int):
        self._prog.append(DW_LNS_set_file)
        self._prog += self._uleb128(file_idx)

    def _emit_copy(self):
        self._prog.append(DW_LNS_copy)

    # ------------------------------------------------------------------
    def build_program(self, rows: list[DumpRow], main_filename: str,
                     sec_spans: list[tuple | None] | None = None):
        """
        Walk dump rows and emit DWARF-2 line number opcodes.

        Rows are grouped by section_index.  Each group gets its own address
        sequence: set_address → (advance_pc / advance_line / copy)* →
        end_sequence.  This prevents rows from different sections whose
        address counters both start at 0 from colliding in the line table.

        For a flat binary every row has section_index=0 so only one sequence
        is emitted — identical behaviour to the original code.
        """
        if not rows:
            return

        self.register_file(main_filename)

        # Which sections to include in the line table.
        # For ELF/COFF object files all sections start at addr=0; emitting
        # multiple sequences from addr=0 confuses GDB's line lookup, so we
        # only emit section 0 (the executable text section).
        # For format binary the kernel may have multiple code regions with
        # distinct non-overlapping address ranges (e.g. boot code at
        # 0x0..0x1ffff and kernel at 0x80000000+). All of them must appear
        # in the line table so that GDB can resolve source lines anywhere.
        if sec_spans is not None and all(
            sp is None or sp == (0, 0)
            for sp in (sec_spans or [])
        ):
            # Object-file mode: all addresses 0-relative, only emit sec 0.
            seen: list[int] = [0]
        else:
            # Emit all sections that have non-macro rows.
            seen_set: set[int] = set()
            for r in rows:
                if r.line and not r.line.is_macro and r.line.line_number > 0:
                    seen_set.add(r.section_index)
            seen = sorted(seen_set)

        for sec_idx in seen:
            sec_rows = [r for r in rows if r.section_index == sec_idx]

            # Sort this section's rows by address.
            sec_rows.sort(key=lambda r: r.addr)

            # Per-sequence register state (reset for each section).
            reg_addr      = 0
            prev_file_idx = 1
            prev_line     = 1
            started       = False

            for row in sec_rows:
                if row.line is None:
                    continue

                # Skip macro-generated lines: their line numbers refer to
                # positions within the macro body, not the source file.
                # Including them produces noise (lines 1,2,3 repeating at
                # many addresses) that obscures real source locations.
                if row.line.is_macro:
                    continue

                filename = row.line.filename or main_filename
                line_num = row.line.line_number
                if line_num == 0:
                    continue

                file_idx = self.register_file(filename)
                addr     = row.addr

                if not started:
                    self._emit_set_address(addr)
                    if file_idx != 1:
                        self._emit_set_file(file_idx)
                        prev_file_idx = file_idx
                    self._emit_advance_line(line_num - 1)
                    prev_line = line_num
                    reg_addr  = addr
                    started   = True
                    self._emit_copy()
                    continue

                if file_idx != prev_file_idx:
                    self._emit_set_file(file_idx)
                    prev_file_idx = file_idx

                if addr > reg_addr:
                    self._emit_advance_pc(addr - reg_addr)
                    reg_addr = addr
                elif addr < reg_addr:
                    # Shouldn't happen within a single section, but handle
                    # it safely with an explicit set_address.
                    self._emit_set_address(addr)
                    reg_addr = addr

                if line_num != prev_line:
                    self._emit_advance_line(line_num - prev_line)
                    prev_line = line_num

                self._emit_copy()

            # End this section's address sequence before starting the next.
            if started:
                self._emit_end_sequence()

    # ------------------------------------------------------------------
    def serialise(self, comp_dir: str = '') -> bytes:
        """Emit the complete .debug_line section bytes including the header."""
        file_table = bytearray()
        for fname in self._files:
            file_table += os.path.normpath(fname).encode('utf-8') + b'\x00'
            file_table += b'\x00'  # directory index = 0
            file_table += b'\x00'  # mtime
            file_table += b'\x00'  # size
        file_table += b'\x00'

        dir_table = b'\x00'

        opcode_lens = bytes(self.STD_OPCODE_LENGTHS[1:])  # 9 bytes

        OPCODE_BASE = len(self.STD_OPCODE_LENGTHS)  # = 10
        header_body = struct.pack('<HIBBBBB',
            2,           # DWARF version
            0,           # header_length placeholder — filled below
            1,           # minimum_instruction_length
            1,           # default_is_stmt
            -5 & 0xFF,   # line_base = -5 as unsigned byte
            14,          # line_range
            OPCODE_BASE, # opcode_base
        ) + opcode_lens + dir_table + bytes(file_table)

        # header_length counts from the end of the header_length field itself
        # to the end of the file_names table, i.e. everything from byte 6 onward.
        header_length_val = len(header_body) - 6
        header_body = header_body[:2] + struct.pack('<I', header_length_val) + header_body[6:]

        program = bytes(header_body) + bytes(self._prog)
        unit_length = len(program)
        return struct.pack('<I', unit_length) + program


# ---------------------------------------------------------------------------
# DWARF-2 .debug_abbrev + .debug_info builder
# ---------------------------------------------------------------------------
def build_debug_info(main_filename: str, comp_dir: str,
                     text_low_pc: int, text_high_pc: int,
                     debug_line_offset: int = 0) -> tuple[bytes, bytes]:
    """
    Build minimal .debug_abbrev and .debug_info sections with a single
    DW_TAG_compile_unit DIE.  Without .debug_info, GDB prints
    "No debugging symbols found" and refuses to use .debug_line for
    source-level commands (b file:line, layout src).

    Returns (abbrev_bytes, info_bytes).

    The DW_AT_stmt_list attribute must contain the offset of the .debug_line
    unit within the .debug_line section — 0 when there is only one CU.

    DW_AT_low_pc / DW_AT_high_pc bracket the code range so that GDB maps
    the CU to the correct address range.
    """
    # ---- Abbreviation table ----
    # Abbrev code 1 = DW_TAG_compile_unit, has_children=DW_CHILDREN_no (0)
    # Attributes:
    #   DW_AT_name        DW_FORM_string   (inline NUL-terminated)
    #   DW_AT_language    DW_FORM_data4
    #   DW_AT_comp_dir    DW_FORM_string
    #   DW_AT_stmt_list   DW_FORM_data4    (offset into .debug_line)
    #   DW_AT_low_pc      DW_FORM_addr     (4 bytes for 32-bit)
    #   DW_AT_high_pc     DW_FORM_addr
    #   0, 0              (end of attribute list)
    # 0                   (end of abbreviation table)
    def uleb128(v):
        out = []
        while True:
            b = v & 0x7F; v >>= 7
            out.append(b | 0x80 if v else b)
            if not v: break
        return bytes(out)

    abbrev = bytearray()
    abbrev += uleb128(1)                    # abbreviation code
    abbrev += uleb128(DW_TAG_compile_unit)
    abbrev += bytes([0])                    # DW_CHILDREN_no
    for at, form in [
        (DW_AT_name,      DW_FORM_string),
        (DW_AT_language,  DW_FORM_data4),
        (DW_AT_comp_dir,  DW_FORM_string),
        (DW_AT_stmt_list, DW_FORM_data4),
        (DW_AT_low_pc,    DW_FORM_addr),
        (DW_AT_high_pc,   DW_FORM_addr),
    ]:
        abbrev += uleb128(at) + uleb128(form)
    abbrev += bytes([0, 0])                 # end of attribute list
    abbrev += bytes([0])                    # end of abbreviation table

    # ---- .debug_info DIE body ----
    # We use inline strings (DW_FORM_string) to avoid needing .debug_str.
    src_name = os.path.basename(main_filename).encode('utf-8') + b'\x00'
    comp_dir_enc = comp_dir.encode('utf-8') + b'\x00'

    die_body = bytearray()
    die_body += uleb128(1)                  # abbreviation code
    die_body += src_name                    # DW_AT_name  (DW_FORM_string)
    die_body += struct.pack('<I', DW_LANG_Mips_Assembler)  # DW_AT_language
    die_body += comp_dir_enc               # DW_AT_comp_dir
    die_body += struct.pack('<I', debug_line_offset)       # DW_AT_stmt_list
    die_body += struct.pack('<I', text_low_pc & 0xFFFFFFFF)   # DW_AT_low_pc
    die_body += struct.pack('<I', text_high_pc & 0xFFFFFFFF)  # DW_AT_high_pc

    # .debug_info section layout:
    #   unit_length (4) — excludes itself
    #   version     (2)
    #   debug_abbrev_offset (4) — always 0 (our .debug_abbrev has one table)
    #   address_size (1)
    #   DIE data
    info_header = struct.pack('<IHIb',
        2 + 4 + 1 + len(die_body),   # unit_length: version(2)+abbrev_off(4)+addr_size(1)+DIE
        2,                             # DWARF version
        0,                             # debug_abbrev_offset
        4,                             # address_size (32-bit)
    )
    info = info_header + bytes(die_body)
    return bytes(abbrev), info


# ---------------------------------------------------------------------------
# ELF builder
# ---------------------------------------------------------------------------
class ElfBuilder:
    """
    Constructs a minimal 32-bit LE ELF with:
      SHT_NULL        (required index 0)
      SHT_PROGBITS    .text         (loadable anchor, empty body)
      SHT_PROGBITS    .debug_abbrev
      SHT_PROGBITS    .debug_info
      SHT_PROGBITS    .debug_line
      SHT_STRTAB      .strtab       (symbol name strings)
      SHT_SYMTAB      .symtab
      SHT_STRTAB      .shstrtab     (section name strings)
    """

    def __init__(self):
        self._sections: list[dict] = []
        self._shstrtab = bytearray(b'\x00')

    def _shstrtab_add(self, name: str) -> int:
        off = len(self._shstrtab)
        self._shstrtab += name.encode() + b'\x00'
        return off

    def add_section(self, name: str, sh_type: int, sh_flags: int,
                    data: bytes, sh_link: int = 0, sh_info: int = 0,
                    sh_addralign: int = 1, sh_entsize: int = 0,
                    sh_addr: int = 0) -> int:
        idx = len(self._sections)
        name_off = self._shstrtab_add(name)
        self._sections.append({
            'name_off':    name_off,
            'sh_type':     sh_type,
            'sh_flags':    sh_flags,
            'sh_addr':     sh_addr,
            'data':        data,
            'sh_link':     sh_link,
            'sh_info':     sh_info,
            'sh_addralign':sh_addralign,
            'sh_entsize':  sh_entsize,
        })
        return idx

    def build(self, entry: int = 0) -> bytes:
        shstrtab_name_off = self._shstrtab_add('.shstrtab')
        shstrtab_idx = len(self._sections)
        self._sections.append({
            'name_off':     shstrtab_name_off,
            'sh_type':      SHT_STRTAB,
            'sh_flags':     SHF_NONE,
            'data':         bytes(self._shstrtab),
            'sh_link':      0,
            'sh_info':      0,
            'sh_addralign': 1,
            'sh_entsize':   0,
        })

        ELF_HEADER_SIZE = 52
        PH_ENTRY_SIZE   = 32
        SH_ENTRY_SIZE   = 40
        e_shnum         = len(self._sections) + 1  # +1 for SHT_NULL

        PT_LOAD = 1
        PF_R    = 0x4
        PF_W    = 0x2
        PF_X    = 0x1
        SHF_ALLOC_FLAG = 0x2

        # One PT_LOAD segment per allocatable section.  All sections have
        # sh_addr=0 so GDB maps each at virtual address 0 with no offset.
        # Having a covering PT_LOAD for every SHF_ALLOC section prevents the
        # "Loadable section outside ELF segments" warning and, crucially,
        # makes GDB's symbol-context resolution work for data sections.
        alloc_secs = [(i, s) for i, s in enumerate(self._sections)
                      if s['sh_flags'] & SHF_ALLOC_FLAG]
        n_phdrs = len(alloc_secs)

        e_phoff = ELF_HEADER_SIZE
        e_shoff = e_phoff + PH_ENTRY_SIZE * n_phdrs
        data_base = e_shoff + SH_ENTRY_SIZE * e_shnum

        section_offsets = []
        offset = data_base
        for sec in self._sections:
            section_offsets.append(offset)
            offset += max(len(sec['data']), 1)

        elf_header = struct.pack('<4sBBBBBxxxxxxx',
            ELFMAG, ELFCLASS32, ELFDATA2LSB,
            1,   # EV_CURRENT
            0,   # ELFOSABI_NONE
            0,
        )
        elf_header += struct.pack('<HHIIIIIHHHHHH',
            ET_EXEC,
            EM_386,
            1,                 # e_version
            entry,
            e_phoff if n_phdrs else 0,
            e_shoff,
            0,                 # e_flags
            ELF_HEADER_SIZE,
            PH_ENTRY_SIZE,
            n_phdrs,
            SH_ENTRY_SIZE,
            e_shnum,
            shstrtab_idx + 1,  # e_shstrndx
        )

        ph_table = b''
        for sec_i, sec in alloc_secs:
            s_off   = section_offsets[sec_i]
            s_vaddr = sec['sh_addr']          # always 0
            s_filesz = max(len(sec['data']), 1)
            s_memsz  = sec.get('sh_size_mem', s_filesz)
            # Executable sections get R+X; writable sections get R+W.
            if sec['sh_flags'] & 0x4:  # SHF_EXECINSTR
                p_flags = PF_R | PF_X
            else:
                p_flags = PF_R | PF_W
            ph_table += struct.pack('<IIIIIIII',
                PT_LOAD,
                s_off,
                s_vaddr,
                s_vaddr,
                s_filesz,
                s_memsz,
                p_flags,
                1,              # p_align=1: no page alignment for debug ELF
            )

        def sh_entry(name_off, sh_type, sh_flags, sh_addr, sh_offset,
                     sh_size, sh_link, sh_info, sh_addralign, sh_entsize):
            return struct.pack('<IIIIIIIIII',
                name_off, sh_type, sh_flags, sh_addr, sh_offset,
                sh_size,  sh_link, sh_info,  sh_addralign, sh_entsize)

        sh_table = sh_entry(0,0,0,0,0,0,0,0,0,0)  # SHT_NULL
        for i, sec in enumerate(self._sections):
            sh_table += sh_entry(
                sec['name_off'],
                sec['sh_type'],
                sec['sh_flags'],
                sec.get('sh_addr', 0),
                section_offsets[i],
                len(sec['data']),
                sec['sh_link'],
                sec['sh_info'],
                sec['sh_addralign'],
                sec['sh_entsize'],
            )

        body = b''.join(sec['data'] for sec in self._sections)
        return elf_header + ph_table + sh_table + body


# ---------------------------------------------------------------------------
# Symbol table builder
# ---------------------------------------------------------------------------
def build_symtab(symbols: list[FasSymbol], sec_elf_indices: list[int],
                 sec_spans: list[tuple | None],
                 binary_format: bool = False,
                 dump_addr_set: set | None = None):
    """
    Returns (symtab_bytes, strtab_bytes, n_local).

    sec_elf_indices maps section_index → ELF section index in the output file.
    sec_spans       maps section_index → (lo_addr, hi_addr) or None.
    binary_format   True when ALL symbols have val_type==0 (format binary).

    Symbol classification:
      is_external=True               → SHN_UNDEF  (external reference)
      val_type != 0                    → shndx = sec_elf_indices[sym.section_index]
      val_type == 0, binary_format,
        value within sec span          → shndx = section  (format binary label)
      val_type == 0 otherwise          → SHN_ABS (struct offset / pure constant)

    binary_format is set when no symbol in the file has val_type!=0, which
    happens with 'format binary'.  In that mode FASM bakes all addresses
    directly into the output and marks every label val_type=0 — the span
    check then discriminates real labels from compile-time constants.
    When val_type!=0 symbols exist (format ELF / PE), val_type is reliable
    and the span check is not applied.
    """
    strtab = bytearray(b'\x00')

    def add_str(s: str) -> int:
        nonlocal strtab
        off = len(strtab)
        strtab += s.encode('utf-8', errors='replace') + b'\x00'
        return off

    SYM_SIZE = 16
    entries = []
    for sym in symbols:
        name_off = add_str(sym.name)

        if sym.is_external:
            # External reference: field+20 high bit was set (per spec Table 2).
            # Emit as SHN_UNDEF so GDB doesn't use it for address lookups.
            st_type = STT_NOTYPE
            st_bind = STB_GLOBAL
            st_info = (st_bind << 4) | st_type
            entry = struct.pack('<IIIBBH',
                name_off,
                0,
                0,
                st_info,
                STV_DEFAULT,
                0,          # SHN_UNDEF
            )
        elif sym.val_type == VTYPE_ABSOLUTE:
            # val_type==0: in format ELF/PE this reliably means a compile-time
            # constant or struct field offset → SHN_ABS.
            # In format binary ALL symbols have val_type=0, so we use the dump
            # address set: if any dump row was assembled at this address it is a
            # real code/data label; otherwise it is a constant or struct offset.
            # This supersedes the old span-range check which failed for kernels
            # mixing boot-code (phys 0x0..0x1ffff) with kernel code (0x80000000+):
            # the 128 MB window excluded the boot region and the per-section span
            # missed functions whose dump rows landed in a different section.
            val  = sym.value & 0xFFFFFFFF
            is_real = (binary_format
                       and dump_addr_set is not None
                       and val in dump_addr_set)
            if is_real:
                # Real code/data label.
                shndx   = sec_elf_indices[min(sym.section_index,
                                              len(sec_elf_indices) - 1)]
                st_type = STT_NOTYPE
                st_bind = STB_GLOBAL
                st_info = (st_bind << 4) | st_type
                entry = struct.pack('<IIIBBH',
                    name_off, val, 0, st_info, STV_DEFAULT, shndx,
                )
            else:
                # Compile-time constant or struct field offset → SHN_ABS.
                st_type = STT_OBJECT
                st_bind = STB_GLOBAL
                st_info = (st_bind << 4) | st_type
                entry = struct.pack('<IIIBBH',
                    name_off, val, sym.data_size, st_info, STV_DEFAULT, SHN_ABS,
                )
        else:
            # Runtime virtual address in a specific output section.
            # st_size=0: FASM's dsize is unreliable as a code-extent metric.
            shndx   = sec_elf_indices[sym.section_index]
            st_type = STT_NOTYPE
            st_bind = STB_GLOBAL
            st_info = (st_bind << 4) | st_type
            entry = struct.pack('<IIIBBH',
                name_off,
                sym.value & 0xFFFFFFFF,
                0,
                st_info,
                STV_DEFAULT,
                shndx,
            )
        entries.append(entry)

    null_sym = b'\x00' * SYM_SIZE
    symtab = null_sym + b''.join(entries)
    n_local = 1  # only the mandatory null symbol is LOCAL

    return bytes(symtab), bytes(strtab), n_local


# ---------------------------------------------------------------------------
# Main converter
# ---------------------------------------------------------------------------
def convert(fas_path: str, elf_path: str, rebase: int, verbose: bool):
    with open(fas_path, 'rb') as f:
        data = f.read()

    print(f"[*] Parsing {fas_path} ({len(data)} bytes) …")
    parser = FasParser(data, rebase=rebase, verbose=verbose)
    parser.parse()

    print(f"[*] {len(parser.symbols)} symbols, {len(parser.dump)} dump rows "
          f"across {parser.n_sections} output section(s)")

    # --- Determine per-section address spans ---
    # (Computed first so build_program can use them to filter preamble rows.)
    # For each detected output section we record [min_addr, max_addr] using
    # only dump rows that belong to it.  These spans drive:
    #   • DW_AT_low_pc / DW_AT_high_pc in .debug_info
    #   • The ELF section sh_addr (always 0) and the PT_LOAD anchor
    # For a flat binary there is one section; for format ELF there may be several.
    #
    # Address-span computation uses the same median-windowing heuristic as
    # before to filter out stray small values (struct offsets that leaked
    # through as vtype!=0).  We apply it globally then per section.
    SHF_ALLOC     = 0x2
    SHF_EXECINSTR = 0x4
    SHF_WRITE     = 0x1

    # Determine whether this is an object-file format (ELF/COFF) with a section
    # names table.  In object-file mode ALL addresses are section-relative and
    # legitimately start at 0x0, so we must NOT filter out addr==0.
    # For flat binary / PE, addr==0 rows are pre-code preamble directives and
    # we keep the existing addr>0 guard to exclude them from span computation.
    object_file_mode = len(parser.section_names) > 0

    # Collect all runtime addresses for the global median (used for windowing).
    # In object-file mode include addr==0 (valid section start).
    # In flat/PE mode exclude addr==0 (preamble noise) but also exclude
    # addresses that have no section association (section_index==0 phantom rows).
    if object_file_mode:
        all_rt_addrs = (
            [s.value & 0xFFFFFFFF for s in parser.symbols
             if s.val_type != VTYPE_ABSOLUTE and not s.is_external
             and s.value <= 0xFFFFFFFF] +
            [r.addr for r in parser.dump
             if r.section_index > 0 and r.addr <= 0xFFFFFFFF]
        )
    else:
        all_rt_addrs = (
            [s.value for s in parser.symbols
             if s.val_type != VTYPE_ABSOLUTE and not s.is_external
             and 0 < s.value <= 0xFFFFFFFF] +
            [r.addr for r in parser.dump if 0 < r.addr <= 0xFFFFFFFF]
        )

    if not all_rt_addrs:
        # Object-file with all addresses at 0 (e.g. COFF with only data at offset 0).
        # Use 0 as the median so the window covers everything.
        global_median = 0
    else:
        all_rt_addrs.sort()
        global_median = all_rt_addrs[len(all_rt_addrs) // 2]
    WINDOW = 0x8000000   # 128 MB either side of the median

    # Per-section: gather addresses, apply window filter, compute span.
    # sec_spans[i] = (low_page, high_page) or None if section has no rows.
    sec_spans: list[tuple[int,int] | None] = []
    for sec_idx in range(parser.n_sections):
        if object_file_mode:
            # Include addr==0 for object-file sections (section-relative).
            sec_addrs = [r.addr for r in parser.dump
                         if r.section_index == sec_idx
                         and r.addr <= 0xFFFFFFFF
                         and abs(r.addr - global_median) <= WINDOW]
        else:
            sec_addrs = [r.addr for r in parser.dump
                         if r.section_index == sec_idx
                         and 0 < r.addr <= 0xFFFFFFFF
                         and abs(r.addr - global_median) <= WINDOW]
        if not sec_addrs:
            sec_spans.append(None)
        else:
            lo = min(sec_addrs) & ~0xFFF
            hi = (max(sec_addrs) + 0xFFF) & ~0xFFF
            sec_spans.append((lo, hi))
            print(f"[*] Section {sec_idx}: addr span {lo:#010x}–{hi:#010x}")

    comp_dir = os.path.dirname(os.path.abspath(fas_path))

    # Determine the CU's DW_AT_low_pc/high_pc range.
    # Must span every address that has a line table entry — GDB uses this
    # to decide which CU owns a given address when resolving source locations.
    # We use the exact same row predicate as build_program (non-virtual,
    # non-noinfile, non-macro, real line number), so the CU range is always
    # consistent with what the line table actually contains.
    _line_addrs = [
        r.addr & 0xFFFFFFFF
        for r in parser.dump
        if r.line and not r.line.is_macro and r.line.line_number > 0
    ]
    if _line_addrs and max(_line_addrs) > 0:
        cu_low_pc  = min(_line_addrs)
        cu_high_pc = (max(_line_addrs) + 0xFFF) & ~0xFFF
    else:
        # All addresses are 0 (COFF/ELF object files): cover everything.
        cu_low_pc  = 0
        cu_high_pc = 0xFFFFFFFF

    # --- Build .debug_abbrev + .debug_info ---
    abbrev_bytes, info_bytes = build_debug_info(
        main_filename     = parser._main_filename,
        comp_dir          = comp_dir,
        text_low_pc       = cu_low_pc,
        text_high_pc      = cu_high_pc,
        debug_line_offset = 0,
    )
    print(f"[*] .debug_abbrev: {len(abbrev_bytes)} bytes")
    print(f"[*] .debug_info:   {len(info_bytes)} bytes")

    # --- Assemble ELF ---
    # Section layout (SHT_NULL = index 0, added by ElfBuilder.build()):
    #   For each detected output section (0..n_sections-1):
    #     ELF index = 1 + sec_idx   → named .text / .data / .seg2 …
    #   Then: .debug_abbrev, .debug_info, .debug_line, .strtab, .symtab, .shstrtab
    #
    # All loadable sections get sh_addr=0 so that:
    #   (gdb) add-symbol-file file 0
    # applies zero offset and symbol values are used as-is.

    elf = ElfBuilder()

    # sec_elf_indices[section_index] = ELF section index in the output file.
    sec_elf_indices: list[int] = []

    # Use section names from the FAS section names table when available
    # (ELF/COFF output).  Fall back to conventional names otherwise.
    FALLBACK_NAMES = [".text", ".data", ".bss", ".rodata"]

    for sec_idx in range(parser.n_sections):
        # parser.section_names is 0-based: [0] = FAS section 1 = our section 0.
        if sec_idx < len(parser.section_names):
            name = parser.section_names[sec_idx]
        elif sec_idx < len(FALLBACK_NAMES):
            name = FALLBACK_NAMES[sec_idx]
        else:
            name = f".seg{sec_idx}"

        # All output sections need SHF_ALLOC so GDB maps them into its
        # address space and can resolve symbols that live in them.
        # The PT_LOAD segment emitted by ElfBuilder covers all of them.
        if sec_idx == 0:
            flags = SHF_ALLOC | SHF_EXECINSTR
        else:
            flags = SHF_ALLOC | SHF_WRITE

        elf_idx = elf.add_section(
            name, SHT_PROGBITS, flags,
            b'\x00',        # placeholder byte; GDB reads real bytes from target
            sh_addr      = 0,
            sh_addralign = 1,
        )
        sec_elf_indices.append(elf_idx + 1)   # +1 for the SHT_NULL at index 0

    # --- Build symbol table ---
    # sec_spans uses page-aligned lo/hi; pass the RAW (non-page-aligned) span
    # so that symbols at the exact boundary (e.g. _start==org value) are included.
    raw_sec_spans: list[tuple[int,int] | None] = []
    for sec_idx in range(parser.n_sections):
        sec_addrs = [r.addr for r in parser.dump
                     if r.section_index == sec_idx and r.addr <= 0xFFFFFFFF
                     and abs(r.addr - global_median) <= WINDOW]
        if sec_addrs:
            raw_sec_spans.append((min(sec_addrs), max(sec_addrs)))
        else:
            raw_sec_spans.append(None)

    # --- Build DWARF line program ---
    # Now that raw_sec_spans is available, build_program can filter out
    # pre-code preamble rows (addr=0 for 'format binary'/'format PE' directives)
    # that would otherwise force the line table to start at addr=0 and create
    # a huge advance_pc jump to the real code address, confusing GDB.
    dwarf = DwarfLineProgram()
    dwarf.build_program(parser.dump, parser._main_filename, raw_sec_spans)
    debug_line_bytes = dwarf.serialise()
    print(f"[*] .debug_line: {len(debug_line_bytes)} bytes, "
          f"{len(dwarf._files)} source file(s)")
    if verbose:
        for i, fn in enumerate(dwarf._files, 1):
            print(f"    file {i}: {fn}", file=sys.stderr)

    # Format binary: no section names table (binary/PE/MZ) AND all symbols absolute.
    # In that mode FASM bakes all addresses and marks every label val_type=0,
    # so we use the section span to distinguish real labels from constants.
    binary_format = (len(parser.section_names) == 0 and
                     not any(s.val_type != VTYPE_ABSOLUTE for s in parser.symbols))
    if binary_format:
        print("[*] Format binary detected: using span-check for symbol classification")

    symtab_bytes, strtab_bytes, n_local = build_symtab(
        parser.symbols, sec_elf_indices, raw_sec_spans, binary_format,
        dump_addr_set = parser.dump_addr_set if binary_format else None,
    )
    # Recount based on actual classification
    def _is_abs(s):
        if s.is_external: return False
        if s.val_type != VTYPE_ABSOLUTE: return False
        val = s.value & 0xFFFFFFFF
        if binary_format and val in parser.dump_addr_set:
            return False  # real label (found in dump)
        return True
    ext_count = sum(1 for s in parser.symbols if s.is_external)
    abs_count = sum(1 for s in parser.symbols if _is_abs(s))
    va_count  = len(parser.symbols) - abs_count - ext_count
    print(f"[*] .symtab: {len(parser.symbols)} symbols "
          f"({va_count} virtual-address, {abs_count} absolute/struct-offset,"
          f" {ext_count} external)")

    # .debug_abbrev (must precede .debug_info)
    elf.add_section(".debug_abbrev", SHT_PROGBITS, SHF_NONE, abbrev_bytes)

    # .debug_info — compile-unit DIE
    elf.add_section(".debug_info", SHT_PROGBITS, SHF_NONE, info_bytes)

    # .debug_line
    elf.add_section(".debug_line", SHT_PROGBITS, SHF_NONE, debug_line_bytes)

    # .strtab (symbol name strings)
    strtab_idx = elf.add_section(".strtab", SHT_STRTAB, SHF_NONE, strtab_bytes)

    # .symtab — sh_link points to .strtab (ELF index = internal idx + 1)
    elf.add_section(
        ".symtab", SHT_SYMTAB, SHF_NONE, symtab_bytes,
        sh_link      = strtab_idx + 1,
        sh_info      = n_local,
        sh_addralign = 4,
        sh_entsize   = 16,
    )

    elf_bytes = elf.build(entry=0)

    with open(elf_path, "wb") as f:
        f.write(elf_bytes)

    print(f"[*] Written {elf_path} ({len(elf_bytes)} bytes)")
    print()
    print("GDB usage:")
    print(f"  (gdb) add-symbol-file {elf_path} 0")
    print( "  (gdb) info functions")
    print( "  (gdb) b _start")
    print( "  (gdb) b elfdemo.asm:22")
    print( "  (gdb) layout src")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description='Convert a FASM .fas debug file to a GDB-loadable ELF.')
    ap.add_argument('fas', help='Input .fas file')
    ap.add_argument('-o', '--output', help='Output ELF path (default: <input>_dbg.elf)')
    ap.add_argument('--rebase', default='0',
                    help='Hex offset to add to all addresses '
                         '(use when load VA differs from org, e.g. --rebase 0x10000)')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='Print every symbol and line entry')
    args = ap.parse_args()

    rebase = int(args.rebase, 16)
    out    = args.output or (os.path.splitext(args.fas)[0] + '_dbg.elf')

    convert(args.fas, out, rebase, args.verbose)

if __name__ == '__main__':
    main()
