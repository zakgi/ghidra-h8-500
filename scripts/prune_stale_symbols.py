# Remove auto-generated functions and labels that no longer have any inbound
# references. After a slaspec change that changes how addresses get resolved
# (in our case, the CP-from-inst_next fix that re-targeted JSR @addr16:16),
# the old destinations get orphaned -- functions and labels persist with no
# callers, no XRefs, no purpose.
#
# Conservative: only touches symbols Ghidra auto-generated (FUN_, DAT_, LAB_,
# UNK_, SUB_). User-named symbols are left alone. Asks for confirmation
# before removing.
#
#@author Giammarco Zacheo & Claude
#@category SC55mkII
#@menupath SC55mkII.Prune stale symbols
#@runtime Jython

from ghidra.program.model.symbol import SourceType, SymbolType

AUTO_PREFIXES = ("FUN_", "SUB_", "DAT_", "LAB_", "UNK_")

def is_auto(symbol):
    """True if Ghidra auto-generated this symbol (default-named, no user input)."""
    if symbol.getSource() != SourceType.DEFAULT and \
       symbol.getSource() != SourceType.ANALYSIS:
        return False
    name = symbol.getName()
    return any(name.startswith(p) for p in AUTO_PREFIXES)

def has_inbound_refs(addr):
    rm = currentProgram.getReferenceManager()
    return rm.hasReferencesTo(addr)

def main():
    prog = currentProgram
    fm = prog.getFunctionManager()
    st = prog.getSymbolTable()

    stale_funcs = []
    for func in fm.getFunctions(True):
        entry = func.getEntryPoint()
        # Skip thunks, externals, and anything user-named.
        if func.isThunk() or func.isExternal():
            continue
        if func.getSymbol().getSource() not in (SourceType.DEFAULT, SourceType.ANALYSIS):
            continue
        if has_inbound_refs(entry):
            continue
        # Also skip if the function is the entry point of the program.
        # (Reset vector etc. has no XRef but is essential.)
        if entry.equals(prog.getImageBase()):
            continue
        stale_funcs.append(func)

    stale_labels = []
    for sym in st.getSymbolIterator():
        if sym.getSymbolType() != SymbolType.LABEL:
            continue
        if not is_auto(sym):
            continue
        if has_inbound_refs(sym.getAddress()):
            continue
        stale_labels.append(sym)

    print("Stale auto-generated functions (no callers):")
    for f in stale_funcs[:200]:
        print("  %s at %s" % (f.getName(), f.getEntryPoint()))
    if len(stale_funcs) > 200:
        print("  ... and %d more" % (len(stale_funcs) - 200))
    print("Total: %d functions" % len(stale_funcs))
    print("")
    print("Stale auto-generated labels (no XRefs):")
    for s in stale_labels[:200]:
        print("  %s at %s" % (s.getName(), s.getAddress()))
    if len(stale_labels) > 200:
        print("  ... and %d more" % (len(stale_labels) - 200))
    print("Total: %d labels" % len(stale_labels))
    print("")

    if not stale_funcs and not stale_labels:
        print("Nothing to prune.")
        return

    confirm = askYesNo("Prune stale symbols",
                       "Remove %d functions and %d labels?" %
                       (len(stale_funcs), len(stale_labels)))
    if not confirm:
        print("Cancelled.")
        return

    for f in stale_funcs:
        fm.removeFunction(f.getEntryPoint())
    for s in stale_labels:
        s.delete()
    print("Removed %d functions and %d labels." %
          (len(stale_funcs), len(stale_labels)))

main()
