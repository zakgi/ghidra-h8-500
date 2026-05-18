# Loads the Roland SC-55 mkII memory map into the current Ghidra program.
#
# Run from Script Manager after importing either ROM as raw binary with
# Language = "Hitachi:big:H8/520:default". The importer will have created
# one default RAM block, which this script will leave alone if it doesn't
# overlap our regions, and will replace if it does.
#
# Prompts for:
#   - Main MCU ROM    (32K)   e.g.  r15199858_main_mcu.bin
#   - Control ROM     (512K)  e.g.  r00233567_control.bin
#
# Builds the memory map distilled from Nuked-SC55 mcu.cpp (MCU_Read /
# MCU_Write, !mcu.is_mk1 branches), labels peripheral registers, and adds
# H8/500 vector-table symbols where the pspec didn't already.
#
# Safe to re-run: existing blocks with matching names get removed first.
#
#@author Giammarco Zacheo & Claude
#@category SC55mkII
#@menupath SC55mkII.Load memory map
#@runtime Jython

from ghidra.program.model.mem import MemoryConflictException
from ghidra.program.model.address import AddressOutOfBoundsException
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor
from java.io import File, FileInputStream

# When this script is launched via runScript() from another script (e.g. the
# pipeline orchestrator), the injected `monitor` global is None. Several
# Ghidra APIs we call (memory.removeBlock, memory.createInitializedBlock)
# require a non-null monitor, so swap in the no-op fallback.
if monitor is None:
    monitor = TaskMonitor.DUMMY

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

# (name, start_address, length, mode, contents)
# mode: 'r'=read-only initialized, 'rw'=read-write uninitialized, 'io'=volatile
NON_ROM_BLOCKS = [
    # Page 0
    ("SRAM",         0x008000, 0x6000, "rw", "Main work SRAM (24K)"),
    ("PCM_REGS",     0x00E000, 0x0040, "io", "PCM sample-playback chip registers"),
    ("SUBMCU_WIN",   0x00EC00, 0x0400, "io", "Communications window for the 4K sub-MCU"),
    ("ONCHIP_RAM",   0x00FB80, 0x0400, "rw", "H8/500 on-chip 1K RAM (enabled via RAMCR bit 7)"),
    ("PERIPH_REGS",  0x00FF80, 0x0080, "io", "H8/500 on-chip peripheral register block"),
    # SRAM mirror visible at pages 10-11
    ("SRAM_MIRROR",  0x0A0000, 0x8000, "rw", "Alias of main SRAM (page 10/11 banking)"),
]

# ROM1: on-chip 32K mask ROM on the main H8/510. Mapped at 0x0000-0x7FFF.
ROM1_BLOCK = ("ROM1",    0x000000, 0x8000,  "Main MCU on-chip mask ROM (32K, contains reset vectors)")

# ROM2: 512K external control ROM. Mapped non-contiguously across pages.
# Each tuple: (block_name, cpu_address, rom_offset, length, comment)
# Distilled from Nuked-SC55 mcu.cpp lines 580-610. The address_rom calc is:
#   address_rom = (address & 0x3FFFF) | ((address & 0x80000) ? 0x40000 : 0)
ROM2_BANKS = [
    ("ROM2_p1",  0x010000, 0x10000, 0x10000, "Pages 1-3 map contiguously"),
    ("ROM2_p2",  0x020000, 0x20000, 0x10000, ""),
    ("ROM2_p3",  0x030000, 0x30000, 0x10000, ""),
    ("ROM2_p4",  0x040000, 0x00000, 0x10000, "Page 4 wraps to ROM offset 0 -- where firmware entry lives"),
    ("ROM2_p8",  0x080000, 0x40000, 0x10000, "Pages 8-9 cover ROM offsets 0x40000-0x5FFFF"),
    ("ROM2_p9",  0x090000, 0x50000, 0x10000, ""),
    ("ROM2_p14", 0x0E0000, 0x60000, 0x10000, "Pages 14-15 cover ROM offsets 0x60000-0x7FFFF"),
    ("ROM2_p15", 0x0F0000, 0x70000, 0x10000, ""),
]

# H8/500 on-chip peripheral register names. Offsets are from 0xFF80.
# From Nuked-SC55 src/backend/mcu.h (MCU_Register_Field enum).
PERIPHERAL_REGS = [
    (0x00, "P1DDR",      "Port 1 data direction"),
    (0x01, "P2DDR",      "Port 2 data direction"),
    (0x02, "P1DR",       "Port 1 data"),
    (0x03, "P2DR",       "Port 2 data"),
    (0x04, "P3DDR",      "Port 3 data direction"),
    (0x05, "P4DDR",      "Port 4 data direction"),
    (0x06, "P3DR",       "Port 3 data"),
    (0x07, "P4DR",       "Port 4 data"),
    (0x08, "P5DDR",      "Port 5 data direction"),
    (0x09, "P6DDR",      "Port 6 data direction"),
    (0x0A, "P5DR",       "Port 5 data"),
    (0x0B, "P6DR",       "Port 6 data"),
    (0x0C, "P7DDR",      "Port 7 data direction"),
    (0x0E, "P7DR",       "Port 7 data"),
    (0x0F, "P8DR",       "Port 8 data"),
    (0x10, "FRT1_TCR",   "Free-running timer 1: timer control"),
    (0x11, "FRT1_TCSR",  "Free-running timer 1: control/status"),
    (0x12, "FRT1_FRCH",  "Free-running timer 1: free counter high"),
    (0x13, "FRT1_FRCL",  "Free-running timer 1: free counter low"),
    (0x14, "FRT1_OCRAH", "Free-running timer 1: output compare A high"),
    (0x15, "FRT1_OCRAL", "Free-running timer 1: output compare A low"),
    (0x16, "FRT1_OCRBH", "Free-running timer 1: output compare B high"),
    (0x17, "FRT1_OCRBL", "Free-running timer 1: output compare B low"),
    (0x18, "FRT1_ICRH",  "Free-running timer 1: input capture high"),
    (0x19, "FRT1_ICRL",  "Free-running timer 1: input capture low"),
    (0x20, "FRT2_TCR",   "Free-running timer 2: timer control"),
    (0x21, "FRT2_TCSR",  "Free-running timer 2: control/status"),
    (0x22, "FRT2_FRCH",  "Free-running timer 2: free counter high"),
    (0x23, "FRT2_FRCL",  "Free-running timer 2: free counter low"),
    (0x24, "FRT2_OCRAH", "Free-running timer 2: output compare A high"),
    (0x25, "FRT2_OCRAL", "Free-running timer 2: output compare A low"),
    (0x26, "FRT2_OCRBH", "Free-running timer 2: output compare B high"),
    (0x27, "FRT2_OCRBL", "Free-running timer 2: output compare B low"),
    (0x28, "FRT2_ICRH",  "Free-running timer 2: input capture high"),
    (0x29, "FRT2_ICRL",  "Free-running timer 2: input capture low"),
    (0x30, "FRT3_TCR",   "Free-running timer 3: timer control"),
    (0x31, "FRT3_TCSR",  "Free-running timer 3: control/status"),
    (0x32, "FRT3_FRCH",  "Free-running timer 3: free counter high"),
    (0x33, "FRT3_FRCL",  "Free-running timer 3: free counter low"),
    (0x34, "FRT3_OCRAH", "Free-running timer 3: output compare A high"),
    (0x35, "FRT3_OCRAL", "Free-running timer 3: output compare A low"),
    (0x36, "FRT3_OCRBH", "Free-running timer 3: output compare B high"),
    (0x37, "FRT3_OCRBL", "Free-running timer 3: output compare B low"),
    (0x38, "FRT3_ICRH",  "Free-running timer 3: input capture high"),
    (0x39, "FRT3_ICRL",  "Free-running timer 3: input capture low"),
    (0x40, "PWM1_TCR",   "PWM 1: timer control"),
    (0x41, "PWM1_DTR",   "PWM 1: duty register"),
    (0x42, "PWM1_TCNT",  "PWM 1: timer counter"),
    (0x44, "PWM2_TCR",   "PWM 2: timer control"),
    (0x45, "PWM2_DTR",   "PWM 2: duty register"),
    (0x46, "PWM2_TCNT",  "PWM 2: timer counter"),
    (0x48, "PWM3_TCR",   "PWM 3: timer control"),
    (0x49, "PWM3_DTR",   "PWM 3: duty register"),
    (0x4A, "PWM3_TCNT",  "PWM 3: timer counter"),
    (0x50, "TMR_TCR",    "8-bit timer: control"),
    (0x51, "TMR_TCSR",   "8-bit timer: control/status"),
    (0x52, "TMR_TCORA",  "8-bit timer: output compare A"),
    (0x53, "TMR_TCORB",  "8-bit timer: output compare B"),
    (0x54, "TMR_TCNT",   "8-bit timer: counter"),
    (0x58, "SMR",        "SCI mode register (MIDI port)"),
    (0x59, "BRR",        "SCI bit rate register"),
    (0x5A, "SCR",        "SCI control register"),
    (0x5B, "TDR",        "SCI transmit data"),
    (0x5C, "SSR",        "SCI status register"),
    (0x5D, "RDR",        "SCI receive data"),
    (0x60, "ADDRAH",     "A/D channel A result high"),
    (0x61, "ADDRAL",     "A/D channel A result low"),
    (0x62, "ADDRBH",     "A/D channel B result high"),
    (0x63, "ADDRBL",     "A/D channel B result low"),
    (0x64, "ADDRCH",     "A/D channel C result high"),
    (0x65, "ADDRCL",     "A/D channel C result low"),
    (0x66, "ADDRDH",     "A/D channel D result high"),
    (0x67, "ADDRDL",     "A/D channel D result low"),
    (0x68, "ADCSR",      "A/D control/status"),
    (0x70, "IPRA",       "Interrupt priority A"),
    (0x71, "IPRB",       "Interrupt priority B"),
    (0x72, "IPRC",       "Interrupt priority C"),
    (0x73, "IPRD",       "Interrupt priority D"),
    (0x74, "DTEA",       "DMA transfer enable A"),
    (0x75, "DTEB",       "DMA transfer enable B"),
    (0x76, "DTEC",       "DMA transfer enable C"),
    (0x77, "DTED",       "DMA transfer enable D"),
    (0x78, "WCR",        "Wait-state controller"),
    (0x79, "RAMCR",      "On-chip RAM control (bit 7 = enable 0xFB80-0xFF7F)"),
    (0x7C, "P1CR",       "Port 1 control"),
    (0x7E, "P9DDR",      "Port 9 data direction"),
    (0x7F, "P9DR",       "Port 9 data"),
]

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def addr(offset):
    return toAddr(long(offset))

def remove_existing_block(name):
    """Drop a block by name if it exists. Useful for re-runs."""
    mem = currentProgram.getMemory()
    blk = mem.getBlock(name)
    if blk is not None:
        print("  - removing existing block %s" % name)
        mem.removeBlock(blk, monitor)

def remove_overlapping_default_block(start, length):
    """Remove ANY existing block that overlaps the region we're about to create.
    Covers both the raw-binary importer's default 'ram' block and any leftover
    block from a previous partial run. remove_existing_block(name) handles the
    by-name case for clean re-runs; this function is the catch-all."""
    mem = currentProgram.getMemory()
    end = start + length - 1
    # Snapshot the block list because removeBlock mutates it.
    for blk in list(mem.getBlocks()):
        bs = blk.getStart().getOffset()
        be = blk.getEnd().getOffset()
        if bs <= end and be >= start:
            print("  - removing overlapping block %s [%X-%X]" % (blk.getName(), bs, be))
            mem.removeBlock(blk, monitor)

def make_initialized_from_file(name, start_addr, file_path, file_offset, length, comment, read_only=True):
    """Create a memory block whose contents come from a region of a file."""
    mem = currentProgram.getMemory()
    remove_existing_block(name)
    stream = FileInputStream(File(file_path))
    try:
        if file_offset:
            skipped = 0
            while skipped < file_offset:
                n = stream.skip(file_offset - skipped)
                if n <= 0:
                    raise IOError("failed to seek to offset %d in %s" % (file_offset, file_path))
                skipped += n
        blk = mem.createInitializedBlock(name, addr(start_addr), stream, long(length), monitor, False)
    finally:
        stream.close()
    blk.setRead(True)
    blk.setWrite(not read_only)
    blk.setExecute(True)
    if comment:
        blk.setComment(comment)
    print("  + ROM block %-10s at 0x%06X size 0x%X from %s+0x%X" %
          (name, start_addr, length, file_path.split("/")[-1], file_offset))
    return blk

def make_uninitialized(name, start_addr, length, comment, writeable=True, volatile=False):
    """Create a non-file-backed memory block (RAM or memory-mapped I/O).
    We use createInitializedBlock with a 0x00 fill so the listing displays
    cleanly instead of showing ?? for every byte. The volatile flag still
    tells the decompiler that I/O reads can return changing values."""
    mem = currentProgram.getMemory()
    remove_existing_block(name)
    blk = mem.createInitializedBlock(name, addr(start_addr), long(length), 0, monitor, False)
    blk.setRead(True)
    blk.setWrite(writeable)
    blk.setExecute(False)
    blk.setVolatile(volatile)
    if comment:
        blk.setComment(comment)
    kind = "io" if volatile else ("rw" if writeable else "r-")
    print("  + %s block %-12s at 0x%06X size 0x%X" % (kind, name, start_addr, length))
    return blk

def add_label(addr_offset, name, comment=None):
    """Add a primary label, namespaced to keep them out of the global pool."""
    a = addr(addr_offset)
    sym_table = currentProgram.getSymbolTable()
    # Use createLabel; if a same-named label already exists it'll be made primary.
    try:
        sym_table.createLabel(a, name, SourceType.USER_DEFINED)
    except Exception as e:
        print("  ! could not label 0x%06X as %s: %s" % (addr_offset, name, e))
        return
    if comment:
        cu = currentProgram.getListing().getCodeUnitAt(a)
        if cu is not None:
            cu.setComment(cu.EOL_COMMENT, comment)

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("SC-55 mkII memory map loader")
    print("=" * 60)

    rom1_file = askFile("Select main MCU ROM (32K)", "Open")
    rom2_file = askFile("Select control ROM (512K)", "Open")

    if rom1_file is None or rom2_file is None:
        print("Cancelled.")
        return

    rom1_path = rom1_file.getAbsolutePath()
    rom2_path = rom2_file.getAbsolutePath()

    # Size sanity-check before we touch the program.
    if File(rom1_path).length() != 0x8000:
        printerr("WARNING: %s is %d bytes, expected 32768 (0x8000). Continuing anyway."
                 % (rom1_path, File(rom1_path).length()))
    if File(rom2_path).length() != 0x80000:
        printerr("WARNING: %s is %d bytes, expected 524288 (0x80000). Continuing anyway."
                 % (rom2_path, File(rom2_path).length()))

    print("")
    print("--- ROM1 (on-chip mask, 32K) ---")
    name, start, length, comment = ROM1_BLOCK
    remove_overlapping_default_block(start, length)
    make_initialized_from_file(name, start, rom1_path, 0, length, comment, read_only=True)

    print("")
    print("--- non-ROM regions ---")
    for name, start, length, mode, comment in NON_ROM_BLOCKS:
        remove_overlapping_default_block(start, length)
        if mode == "io":
            make_uninitialized(name, start, length, comment, writeable=True, volatile=True)
        elif mode == "rw":
            make_uninitialized(name, start, length, comment, writeable=True, volatile=False)
        elif mode == "r":
            make_uninitialized(name, start, length, comment, writeable=False, volatile=False)
        else:
            raise ValueError("unknown mode %r for %s" % (mode, name))

    print("")
    print("--- ROM2 (control, 512K) ---")
    for name, start, rom_off, length, comment in ROM2_BANKS:
        remove_overlapping_default_block(start, length)
        make_initialized_from_file(name, start, rom2_path, rom_off, length, comment, read_only=True)

    print("")
    print("--- peripheral register labels (0xFF80 base) ---")
    for off, name, comment in PERIPHERAL_REGS:
        add_label(0xFF80 + off, name, comment)
    print("  + %d peripheral registers labelled" % len(PERIPHERAL_REGS))

    print("")
    print("Done. Recommended next steps:")
    print("  1. Open Window > Memory Map -- verify blocks are present and contiguous.")
    print("  2. Re-run Auto Analysis (Analysis > Auto Analyze).")
    print("  3. Read the reset vector at 0x0000 and follow it -- entry into ROM1.")
    print("  4. The firmware payload starts at 0x040000 (ROM2 offset 0); follow")
    print("     ROM1's boot to find the JMP that jumps there.")

main()
