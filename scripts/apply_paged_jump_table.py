# Apply a paged 16-bit jump table to the current Ghidra program.
#
# Many SC-55 mkII firmware dispatch tables are arrays of bare 16-bit
# addresses, with the high byte (CP) implied by the surrounding code.
# Ghidra's stock pointer types can't model "16-bit value + fixed page" --
# they expect the address bits to all be in the data.
#
# This script lets you say: "starting at address A, there are N 2-byte
# entries; combine each with page P to form a 24-bit target". It then:
#   - Types each entry as a uint16
#   - Adds an EOL comment noting the computed full target
#   - Creates a CODE reference from the entry to (P << 16 | value)
#   - Optionally disassembles the target and promotes it to a function
#
# Idempotent: re-running on the same range refreshes the references
# without leaving duplicates.
#
#@author Giammarco Zacheo & Claude
#@category SC55mkII
#@menupath SC55mkII.Apply paged jump table
#@runtime Jython

from ghidra.program.model.data import WordDataType
from ghidra.program.model.symbol import RefType, SourceType
from ghidra.util.task import TaskMonitor

if monitor is None:
    monitor = TaskMonitor.DUMMY


def main():
    table_start = askAddress("Jump-table start", "Address of the first 16-bit entry:")
    count = askInt("Entry count", "Number of 2-byte entries in the table:")
    page_int = askInt("Page byte", "Page byte to splice into each entry (e.g. 4 for CP=0x04):")
    promote = askYesNo("Promote targets",
                       "Disassemble each target and create a function at it if one doesn't exist?")

    if count <= 0:
        print("Count must be positive.")
        return
    if page_int < 0 or page_int > 0xFF:
        print("Page byte must fit in one byte (0-255).")
        return

    page = page_int & 0xFF
    page_shifted = (page << 16)

    listing = currentProgram.getListing()
    rm = currentProgram.getReferenceManager()
    sym = currentProgram.getSymbolTable()

    n_typed = 0
    n_refs = 0
    n_funcs = 0
    n_skipped = 0

    for i in range(count):
        if monitor.isCancelled():
            break
        entry_addr = table_start.add(i * 2)
        # Read big-endian uint16 from the entry
        try:
            raw = getBytes(entry_addr, 2)
            lo16 = ((raw[0] & 0xFF) << 8) | (raw[1] & 0xFF)
        except Exception as e:
            print("  ! could not read entry %d at %s: %s" % (i, entry_addr, e))
            n_skipped += 1
            continue

        target_int = page_shifted | lo16
        target_addr = toAddr(long(target_int))

        # Type the entry as word
        try:
            listing.clearCodeUnits(entry_addr, entry_addr.add(1), False)
            listing.createData(entry_addr, WordDataType())
            n_typed += 1
        except Exception as e:
            print("  ! could not type entry at %s: %s" % (entry_addr, e))

        # Replace any previous code-style refs from this address with one
        # pointing at the computed full target.
        for ref in list(rm.getReferencesFrom(entry_addr)):
            if ref.getReferenceType().isFlow() or ref.getReferenceType() == RefType.COMPUTED_JUMP \
               or ref.getReferenceType() == RefType.DATA:
                rm.delete(ref)
        rm.addMemoryReference(entry_addr, target_addr,
                              RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, 0)
        n_refs += 1

        # EOL comment so the entry shows what it resolves to even in plain views
        listing.setComment(entry_addr, 0,
                           "-> %06X (page %02X | %04X)" % (target_int, page, lo16))

        if promote:
            fn = currentProgram.getFunctionManager().getFunctionAt(target_addr)
            if fn is None:
                # Disassemble if not yet disassembled, then promote.
                try:
                    if listing.getInstructionAt(target_addr) is None:
                        disassemble(target_addr)
                    createFunction(target_addr, None)
                    n_funcs += 1
                except Exception as e:
                    print("  ! could not promote %s to function: %s" %
                          (target_addr, e))

    print("Done: %d entries typed, %d references added, %d new functions, %d skipped." %
          (n_typed, n_refs, n_funcs, n_skipped))

main()
