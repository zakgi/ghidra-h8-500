# Apply SC-55 mkII control ROM data-structure layout to the Ghidra project.
#
# Ports the knowledge in picomt32emu/sc55/src/control_rom.{hpp,cpp} into
# Ghidra: defines the layout structs, applies them at the known offsets in
# ROM2 (the 512K control firmware) and ROM1 (the 32K main MCU mask ROM), and
# labels each entry with the embedded name string when present.
#
# After this runs the project will have:
#   - SC55_Sample, SC55_Partial, SC55_InstPartial, SC55_Instrument,
#     SC55_DrumSet structs defined in /SC55mkII data type category
#   - Each entry in the instrument / partial / sample / drum tables in
#     ROM2 typed as the appropriate struct, labelled by its embedded name
#   - The variations table typed as a 128x128 uint16 matrix
#   - The known lookup tables in both ROM2 and ROM1 labelled by their role
#
# Run AFTER load_sc55mkii.py (needs the memory map in place) and AFTER the
# first auto-analysis pass. Safe to re-run; existing same-named labels are
# left as-is and structs already applied are skipped.
#
# Origin: SC-55 mkII control ROM decoder, libEmuSC (LGPL-2.1), via
# picomt32emu fork (Skjelten / Kitrinx / NewRisingSun). Offsets verified
# against kBanksSc55, kSc55mkIIProgLut, kSc55mkIICpuLut.
#
#@author Giammarco Zacheo & Claude
#@category SC55mkII
#@menupath SC55mkII.Apply control ROM layout
#@runtime Jython

from ghidra.program.model.data import (
    CategoryPath,
    StructureDataType,
    ArrayDataType,
    ByteDataType,
    CharDataType,
    SignedByteDataType,
    WordDataType,
    DWordDataType,
)
from ghidra.program.model.symbol import SourceType

CAT = CategoryPath("/SC55mkII")

# --- Bank offsets in ROM2 (CPU == ROM2 file offsets for pages 1-3) -----------

# kBanksSc55 from control_rom.hpp
BANKS = [0x10000, 0x1BD00, 0x1DEC0, 0x20000, 0x2BD00, 0x2DEC0, 0x30000, 0x38000]

INSTRUMENTS_BANK_A = (BANKS[0], BANKS[1])  # 0x10000 .. 0x1BD00, 216 bytes each
INSTRUMENTS_BANK_B = (BANKS[3], BANKS[4])  # 0x20000 .. 0x2BD00
PARTIALS_BANK_A    = (BANKS[1], BANKS[2])  # 0x1BD00 .. 0x1DEC0, 60 bytes each
PARTIALS_BANK_B    = (BANKS[4], BANKS[5])  # 0x2BD00 .. 0x2DEC0
SAMPLES_BANK_A     = (BANKS[2], BANKS[3])  # 0x1DEC0 .. 0x20000, 16 bytes each
SAMPLES_BANK_B     = (BANKS[5], BANKS[6])  # 0x2DEC0 .. 0x30000
VARIATIONS_START   = BANKS[6]               # 0x30000, 128 rows * 128 cols * 2 bytes
DRUMSETS_LUT       = BANKS[7]               # 0x38000, 128-byte instrument-set lookup
DRUMSETS_START     = BANKS[7] + 128         # 0x38080, 1164 bytes each
DRUMSETS_END       = 0x3C028                # from read_drum_sets_'s upper bound

# Lookup table offsets in ROM2 (kSc55mkIIProgLut) -- both as ROM2 file offsets
# AND CPU addresses, since this whole region maps 1:1 in pages 1-3.
PROG_LUT = [
    ("VelocityCurves", 0x3D1E8, 12 * 128),  # 12 curves of 128 bytes each (mkII)
    ("KeyMapperIndex", 0x3DD7C, 136 * 2),   # 136 int16 entries
    ("KeyMapper",      0x3DE8C, 0x140),     # variable-size lookup, ~320 bytes
]

# Lookup table offsets in ROM1 (kSc55mkIICpuLut). ROM1 is the 32K main_mcu.
CPU_LUT = [
    ("PitchParamScale",      0x1310, 21 * 2),
    ("EnvTimeKeyFollowSens", 0x650E, 21),
    ("EnvTimeScale",         0x653A, 256 * 2),
    ("EnvelopeTime",         0x6C86, 128 * 2),
    ("LFORate",              0x6486, 128 * 2),
    ("LFODelayTime",         0x6E86, 128 * 2),
    ("LFOTVFDepth",          0x6F86, 128 * 2),
    ("LFOTVPDepth",          0x7086, 128 * 2),
    ("LFOSine",              0x7186, 130),
    ("TVFCutoffFreqKF",      0x7246, 21 * 2),
    ("TVFCutoffVSens",       0x7270, 11 * 2),
    ("TVFEnvDepth",          0x7286, 128 * 2),
    ("TVFCutoffFreq",        0x7386, 129 * 2),
    ("TVFResonanceFreq",     0x7488, 256),
    ("TVFResonance",         0x758A, 128),
    ("PitchEnvVelSens1",     0x763A, 11 * 2),
    ("PitchEnvVelSens2",     0x7650, 11 * 2),
    ("PitchEnvDepth",        0x7666, 128 * 2),
    ("TVFEnvScale",          0x7766, 64),
    ("PortamentoRate",       0x77A6, 128 * 2),
    ("EnvSegmentStep",       0x652E, 12),
    ("EnvSegmentCurve",      0x687A, 9),
    ("TVAEnvExpChange",      0x6A84, 257 * 2),
    ("TVABiasLevel",         0x673A, 130),
    ("TVAPanpot",            0x6A03, 129),
    ("TVALevelIndex",        0x6883, 128),
    ("TVALevel",             0x6903, 256),
    ("PitchFineExp",         0x78EE, 256 * 2),
    ("PitchCoarseExp",       0x7AEE, 47 * 2),
]

# ----------------------------------------------------------------------------
# Struct construction helpers
# ----------------------------------------------------------------------------

def addr(off):
    return toAddr(long(off))

def get_or_create_struct(name, size):
    """Return existing struct of this name, or create empty placeholder.
    Caller is responsible for adding fields up to `size` and packing."""
    dtm = currentProgram.getDataTypeManager()
    existing = dtm.getDataType(CAT, name)
    if existing is not None:
        return existing
    s = StructureDataType(CAT, name, size)
    dtm.addDataType(s, None)
    return dtm.getDataType(CAT, name)

def bd(): return ByteDataType()
def sbd(): return SignedByteDataType()
def cd(): return CharDataType()
def wd(): return WordDataType()
def dwd(): return DWordDataType()

def name_arr(of_type, n):
    return ArrayDataType(of_type, n, of_type.getLength())


def build_structs():
    """Define the SC-55 mkII control ROM layout structs in /SC55mkII category."""
    dtm = currentProgram.getDataTypeManager()

    # --- SC55_Sample (16 bytes) ---
    s = StructureDataType(CAT, "SC55_Sample", 16)
    s.replaceAtOffset( 0, bd(),  1, "volume",      "Volume attenuation (0x7f-0)")
    s.replaceAtOffset( 1, bd(),  1, "address_hi",  "Bank + scrambled address bits 23-16 (wave bank in upper bits)")
    s.replaceAtOffset( 2, wd(),  2, "address_lo",  "address bits 15-0 (big-endian)")
    s.replaceAtOffset( 4, wd(),  2, "portaOffset", "Portamento start offset")
    s.replaceAtOffset( 6, wd(),  2, "sampleLen",   "Sample size")
    s.replaceAtOffset( 8, wd(),  2, "loopLen",     "Loop length (sample_len - loop_len - 1)")
    s.replaceAtOffset(10, bd(),  1, "loopMode",    "0=forward, 1=ping-pong, 2=no loop")
    s.replaceAtOffset(11, bd(),  1, "rootKey",     "Base pitch of sample")
    s.replaceAtOffset(12, wd(),  2, "pitchInit",   "Pitch offset before loop")
    s.replaceAtOffset(14, wd(),  2, "pitchSust",   "Pitch offset from first loop")
    dtm.addDataType(s, None)

    # --- SC55_Partial (60 bytes) ---
    p = StructureDataType(CAT, "SC55_Partial", 60)
    p.replaceAtOffset( 0, name_arr(cd(), 12), 12, "name",   "12-char partial name (space-padded)")
    p.replaceAtOffset(12, name_arr(bd(), 16), 16, "breaks", "Note break-points")
    p.replaceAtOffset(28, name_arr(wd(), 16), 32, "samples","Sample IDs (16 big-endian uint16)")
    dtm.addDataType(p, None)

    # --- SC55_InstPartial (92 bytes) ---
    # Only the fields read by the parser; the rest stay as undefined
    # filler. Names match libemusc's struct member names.
    ip = StructureDataType(CAT, "SC55_InstPartial", 92)
    ip.replaceAtOffset( 1, bd(),  1, "rootKeyOffset",  "")
    ip.replaceAtOffset( 2, wd(),  2, "partialIndex",   "Index into partial table; 0xFFFF if unused")
    ip.replaceAtOffset( 4, bd(),  1, "LFO2Waveform",   "")
    ip.replaceAtOffset( 5, bd(),  1, "LFO2Rate",       "")
    ip.replaceAtOffset( 6, bd(),  1, "LFO2Delay",      "")
    ip.replaceAtOffset( 7, bd(),  1, "LFO2Fade",       "")
    ip.replaceAtOffset( 8, bd(),  1, "TVFFlags",       "")
    ip.replaceAtOffset( 9, sbd(), 1, "panpot",         "[-64..64], default 0x40")
    ip.replaceAtOffset(10, sbd(), 1, "coarsePitch",    "Semitone shift, default 0x40")
    ip.replaceAtOffset(11, sbd(), 1, "finePitch",      "Cent shift, default 0x40")
    ip.replaceAtOffset(12, sbd(), 1, "randPitch",      "")
    ip.replaceAtOffset(13, sbd(), 1, "pitchKeyFlw",    "")
    ip.replaceAtOffset(14, bd(),  1, "TVPLFO1Depth",   "")
    ip.replaceAtOffset(15, bd(),  1, "TVPLFO2Depth",   "")
    ip.replaceAtOffset(16, bd(),  1, "pitchEnvDepth",  "")
    # pitch envelope levels/times
    for offset, fname in [
        (18, "pitchEnvL0"), (19, "pitchEnvL1"), (20, "pitchEnvL2"), (21, "pitchEnvL3"),
        (22, "pitchEnvL5"), (23, "pitchEnvT1"), (24, "pitchEnvT2"), (25, "pitchEnvT3"),
        (26, "pitchEnvT4"), (27, "pitchEnvT5"),
    ]:
        ip.replaceAtOffset(offset, bd(), 1, fname, "")
    for offset, fname in [
        (30, "pitchETKeyFP14"), (31, "pitchETKeyFP5"), (32, "pitchETKeyF14"),
        (33, "pitchETKeyF5"),   (34, "pitchEnvVSens"), (35, "pitchEnvTVSens"),
        (36, "TVFCOFVelCur"),   (37, "TVFBaseFlt"),   (38, "TVFResonance"),
        (39, "TVFType"),        (40, "TVFCFKeyFlwC"), (41, "TVFCFKeyFlw"),
        (42, "TVFLFO1Depth"),   (43, "TVFLFO2Depth"), (44, "TVFEnvDepth"),
        (45, "TVFEnvL1"), (46, "TVFEnvL2"), (47, "TVFEnvL3"), (48, "TVFEnvL4"),
        (49, "TVFEnvL5"), (50, "TVFEnvT1"), (51, "TVFEnvT2"), (52, "TVFEnvT3"),
        (53, "TVFEnvT4"), (54, "TVFEnvT5"),
        (57, "TVFETKeyFP14"), (58, "TVFETKeyFP5"), (59, "TVFETKeyF14"), (60, "TVFETKeyF5"),
        (61, "TVFCOFVSens"),  (62, "TVFETVSens12"), (63, "TVFETVSens35"),
        (64, "TVALvlVelCur"),
        (69, "volume"),       (70, "TVABiasPoint"), (71, "TVABiasLevel"),
        (72, "TVALFO1Depth"), (73, "TVALFO2Depth"),
        (74, "TVAEnvL1"), (75, "TVAEnvL2"), (76, "TVAEnvL3"), (77, "TVAEnvL4"),
        (78, "TVAEnvT1"), (79, "TVAEnvT2"), (80, "TVAEnvT3"), (81, "TVAEnvT4"),
        (82, "TVAEnvT5"),
        (85, "TVAETKeyFP14"), (86, "TVAETKeyFP5"), (87, "TVAETKeyF14"), (88, "TVAETKeyF5"),
        (89, "TVAETVSens12"), (90, "TVAETVSens35"),
    ]:
        ip.replaceAtOffset(offset, bd(), 1, fname, "")
    dtm.addDataType(ip, None)
    ip = dtm.getDataType(CAT, "SC55_InstPartial")  # re-fetch for use as field type

    # --- SC55_Instrument (216 bytes; 32 header + 2*92 partials) ---
    i = StructureDataType(CAT, "SC55_Instrument", 216)
    i.replaceAtOffset( 0, name_arr(cd(), 12), 12, "name", "12-char instrument name")
    i.replaceAtOffset(12, bd(),  1, "volume",        "")
    i.replaceAtOffset(14, bd(),  1, "LFO1Waveform",  "")
    i.replaceAtOffset(15, bd(),  1, "LFO1Rate",      "")
    i.replaceAtOffset(16, bd(),  1, "LFO1Delay",     "")
    i.replaceAtOffset(17, bd(),  1, "LFO1Fade",      "")
    i.replaceAtOffset(18, bd(),  1, "partialsUsed",  "Bits 0-1 = which partials active")
    i.replaceAtOffset(19, bd(),  1, "pitchCurve",    "")
    i.replaceAtOffset(32,  ip, 92, "partial0",      "First partial parameters")
    i.replaceAtOffset(124, ip, 92, "partial1",      "Second partial parameters")
    dtm.addDataType(i, None)

    # --- SC55_DrumSet (1164 bytes) ---
    # 128 uint16 preset table + 7 x 128-byte param arrays + 12-byte name
    d = StructureDataType(CAT, "SC55_DrumSet", 1164)
    d.replaceAtOffset(   0, name_arr(wd(), 128), 256, "preset",      "Per-note instrument reference")
    d.replaceAtOffset( 256, name_arr(bd(), 128), 128, "volume",      "Per-note volume")
    d.replaceAtOffset( 384, name_arr(bd(), 128), 128, "key",         "Per-note key")
    d.replaceAtOffset( 512, name_arr(bd(), 128), 128, "assignGroup", "Per-note assign group (exclusive class)")
    d.replaceAtOffset( 640, name_arr(bd(), 128), 128, "panpot",      "")
    d.replaceAtOffset( 768, name_arr(bd(), 128), 128, "reverb",      "")
    d.replaceAtOffset( 896, name_arr(bd(), 128), 128, "chorus",      "")
    d.replaceAtOffset(1024, name_arr(bd(), 128), 128, "flags",       "0x10=accept noteon, 0x01=accept noteoff")
    d.replaceAtOffset(1152, name_arr(cd(),  12),  12, "name",        "12-char drum kit name")
    dtm.addDataType(d, None)

    print("Defined structs in /SC55mkII")

# ----------------------------------------------------------------------------
# Apply structs at addresses and label by name
# ----------------------------------------------------------------------------

def safe_clear_and_create(address, dtype):
    """Clear whatever is at `address` (and any overlap with the new size)
    then apply `dtype`. Returns the new Data instance, or None on failure."""
    listing = currentProgram.getListing()
    try:
        end = address.add(dtype.getLength() - 1)
        listing.clearCodeUnits(address, end, False)
        return listing.createData(address, dtype)
    except Exception as e:
        print("  ! failed to apply %s at %s: %s" %
              (dtype.getName(), address, e))
        return None

def read_name_at(address, length=12):
    """Read up to `length` ASCII bytes starting at address, stop at first
    non-printable, strip trailing whitespace. Returns None if first byte is
    NUL or 0xFF (= unused slot).

    Note: uses the script-level getBytes(addr, int) convenience from
    FlatProgramAPI, NOT memory.getBytes (which takes a pre-allocated buffer
    and returns a count). The Memory.getBytes signature was the source of
    a previous silent-failure bug here."""
    try:
        raw = getBytes(address, length)  # returns Java byte[] (signed bytes)
    except Exception as e:
        print("  ! getBytes failed at %s: %s" % (address, e))
        return None
    if raw is None or len(raw) == 0:
        return None
    # Java bytes are signed (-128..127). Mask to unsigned for ASCII comparison.
    b0 = raw[0] & 0xFF
    if b0 == 0 or b0 == 0xFF:
        return None
    chars = []
    for c in raw:
        cv = c & 0xFF
        if cv == 0 or cv == 0xFF:
            break
        if 32 <= cv < 127:
            chars.append(chr(cv))
        else:
            return None  # non-printable -> bail
    name = "".join(chars).rstrip()
    return name or None

def sanitize_label(prefix, name, fallback):
    """Build a Ghidra-safe label from a free-form patch name."""
    if not name:
        return "%s_%s" % (prefix, fallback)
    clean = "".join(c if (c.isalnum() or c == "_") else "_" for c in name)
    return "%s_%s_%s" % (prefix, fallback, clean)

def apply_label(address, label):
    st = currentProgram.getSymbolTable()
    try:
        st.createLabel(address, label, SourceType.USER_DEFINED)
    except Exception as e:
        # likely a duplicate; not fatal
        pass

def apply_array_of_struct(start, end, stride, dtype, label_prefix):
    """Walk [start, end) in `stride` increments, applying `dtype` and
    labelling each entry. The struct's first field is assumed to be a
    name string for the label; entries with empty / unused names get a
    generic indexed label."""
    cur = start
    idx = 0
    n_applied = 0
    n_named = 0
    while cur < end:
        a = addr(cur)
        name = read_name_at(a, 12)
        if name is None:
            # Unused slot; skip the storage but advance cursor.
            cur += stride
            idx += 1
            continue
        data = safe_clear_and_create(a, dtype)
        if data is not None:
            label = sanitize_label(label_prefix, name, "%03d" % idx)
            apply_label(a, label)
            n_applied += 1
            n_named += 1
        cur += stride
        idx += 1
    return n_applied, n_named

def apply_drumsets():
    """Drum sets are at DRUMSETS_START..DRUMSETS_END, preceded by a
    128-byte instrument-set lookup at DRUMSETS_LUT."""
    dtm = currentProgram.getDataTypeManager()
    drumset_t = dtm.getDataType(CAT, "SC55_DrumSet")

    # The 128-byte LUT before the drum sets themselves
    lut_dtype = ArrayDataType(ByteDataType(), 128, 1)
    safe_clear_and_create(addr(DRUMSETS_LUT), lut_dtype)
    apply_label(addr(DRUMSETS_LUT), "DrumSets_LUT")
    print("  + labelled drum-set LUT at 0x%05X" % DRUMSETS_LUT)

    cur = DRUMSETS_START
    idx = 0
    n = 0
    while cur < DRUMSETS_END:
        a = addr(cur)
        # Drum-set name lives at offset 1152 of the struct
        name = read_name_at(a.add(1152), 12)
        if name is None or name.startswith("AC."):
            cur += 1164
            idx += 1
            continue
        data = safe_clear_and_create(a, drumset_t)
        if data is not None:
            apply_label(a, sanitize_label("DrumSet", name, "%03d" % idx))
            n += 1
        cur += 1164
        idx += 1
    return n

def apply_variations_table():
    """The variations table is at VARIATIONS_START: 128 rows of 128 uint16."""
    row_t = ArrayDataType(WordDataType(), 128, 2)
    matrix_t = ArrayDataType(row_t, 128, 128 * 2)
    safe_clear_and_create(addr(VARIATIONS_START), matrix_t)
    apply_label(addr(VARIATIONS_START), "Variations_table")
    print("  + labelled variations table at 0x%05X" % VARIATIONS_START)

def apply_lookup_tables():
    """Label each known lookup table and apply a byte-array type."""
    for name, off, size in PROG_LUT:
        t = ArrayDataType(ByteDataType(), size, 1)
        safe_clear_and_create(addr(off), t)
        apply_label(addr(off), "LUT_" + name)
    print("  + labelled %d PROG (ROM2) lookup tables" % len(PROG_LUT))

    for name, off, size in CPU_LUT:
        t = ArrayDataType(ByteDataType(), size, 1)
        safe_clear_and_create(addr(off), t)
        apply_label(addr(off), "LUT_" + name)
    print("  + labelled %d CPU (ROM1) lookup tables" % len(CPU_LUT))

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("Applying SC-55 mkII control ROM layout")
    print("=" * 60)

    build_structs()

    dtm = currentProgram.getDataTypeManager()
    instr_t   = dtm.getDataType(CAT, "SC55_Instrument")
    partial_t = dtm.getDataType(CAT, "SC55_Partial")
    sample_t  = dtm.getDataType(CAT, "SC55_Sample")

    print("")
    print("--- Instruments ---")
    a, n = apply_array_of_struct(INSTRUMENTS_BANK_A[0], INSTRUMENTS_BANK_A[1],
                                  216, instr_t, "Instr_A")
    print("  bank A: %d applied (%d named)" % (a, n))
    a, n = apply_array_of_struct(INSTRUMENTS_BANK_B[0], INSTRUMENTS_BANK_B[1],
                                  216, instr_t, "Instr_B")
    print("  bank B: %d applied (%d named)" % (a, n))

    print("")
    print("--- Partials ---")
    a, n = apply_array_of_struct(PARTIALS_BANK_A[0], PARTIALS_BANK_A[1],
                                  60, partial_t, "Partial_A")
    print("  bank A: %d applied (%d named)" % (a, n))
    a, n = apply_array_of_struct(PARTIALS_BANK_B[0], PARTIALS_BANK_B[1],
                                  60, partial_t, "Partial_B")
    print("  bank B: %d applied (%d named)" % (a, n))

    print("")
    print("--- Samples ---")
    # Samples don't have names; just apply the struct type, no labels.
    for region, label in [
        (SAMPLES_BANK_A, "A"),
        (SAMPLES_BANK_B, "B"),
    ]:
        start, end = region
        cur = start
        n = 0
        while cur < end:
            data = safe_clear_and_create(addr(cur), sample_t)
            if data is not None:
                n += 1
            cur += 16
        print("  bank %s: %d samples typed" % (label, n))

    print("")
    print("--- Variations table ---")
    apply_variations_table()

    print("")
    print("--- Drum sets ---")
    n = apply_drumsets()
    print("  %d drum sets typed and labelled" % n)

    print("")
    print("--- Lookup tables ---")
    apply_lookup_tables()

    print("")
    print("Done. Open the Data Type Manager -> /SC55mkII to see the structs.")
    print("Navigate to 0x10000 for the start of instruments bank A.")

main()
