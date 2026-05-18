# Convert FFFFFFFF entries in the H8/500 vector table from `addr` (pointer)
# to plain 4-byte data, so Ghidra stops trying to resolve them and emitting
# AddressOutOfBoundsException in the listing.
#
# The vector table on the SC-55mkII (max mode) lives at 0x0000-0x00FF, with
# each entry being 4 bytes. Reserved/unused slots are filled with 0xFFFFFFFF
# and should not be interpreted as addresses.
#
# Idempotent: re-running is safe; it only touches FFFFFFFF slots that are
# currently typed as addresses.
#
#@author Giammarco Zacheo & Claude
#@category SC55mkII
#@menupath SC55mkII.Clean unused vectors
#@runtime Jython

from ghidra.program.model.data import DWordDataType

VECTOR_TABLE_START = 0x0000
VECTOR_TABLE_END   = 0x0100   # 64 vectors in max mode

def main():
    prog = currentProgram
    mem  = prog.getMemory()
    lst  = prog.getListing()

    n_cleaned = 0
    cur = toAddr(VECTOR_TABLE_START)
    end = toAddr(VECTOR_TABLE_END)

    while cur.compareTo(end) < 0:
        try:
            val = mem.getInt(cur) & 0xFFFFFFFF
        except Exception:
            cur = cur.add(4)
            continue

        if val == 0xFFFFFFFF:
            # Clear whatever data definition is here, then apply DWord.
            data = lst.getDataAt(cur)
            if data is not None:
                lst.clearCodeUnits(cur, cur.add(3), False)
            try:
                lst.createData(cur, DWordDataType())
                # Comment so the user knows what this is.
                lst.setComment(cur, 0, "Unused / reserved vector slot (0xFFFFFFFF)")
                n_cleaned += 1
                print("  + cleaned vector slot at %s" % cur)
            except Exception as e:
                print("  ! could not retype slot at %s: %s" % (cur, e))

        cur = cur.add(4)

    print("Converted %d unused vector slots from addr to dword." % n_cleaned)

main()
