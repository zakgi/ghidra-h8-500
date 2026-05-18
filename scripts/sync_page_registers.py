# Sync H8/500 page-register context fields onto the matching runtime registers
# at every function's entry point.
#
# Background: the slaspec declares CP_ctx/DP_ctx/EP_ctx/TP_ctx/BR_ctx as
# context-register fields, which Ghidra's *disassembler* propagates correctly
# across the whole program (you see them as "assume CP_ctx = 0x4" lines in
# function headers). But Ghidra's *decompiler* analyzer reads the runtime
# CP/DP/EP/TP/BR registers, which the slaspec doesn't update on cross-
# function boundaries -- the constant-propagation pass starts fresh at each
# function entry with the pspec's default value (0).
#
# This script bridges the two by copying each context field's value at the
# function entry into the matching tracked runtime register. After running
# it, re-run Analysis -> One Shot -> Constant Reference Analyzer for the
# updated values to feed into the decompiler.
#
# Idempotent: safe to re-run after re-analysis. If a function entry's
# context value matches what's already there, no change is made.
#
#@author Giammarco Zacheo & Claude
#@category SC55mkII
#@menupath SC55mkII.Sync page registers
#@runtime Jython

from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger

# context field name -> runtime register name
PAIRS = [
    ("CP_ctx", "CP"),
    ("DP_ctx", "DP"),
    ("EP_ctx", "EP"),
    ("TP_ctx", "TP"),
    ("BR_ctx", "BR"),
]

def main():
    prog = currentProgram
    pctx = prog.getProgramContext()

    # Resolve register objects once.
    pairs = []
    for ctx_name, run_name in PAIRS:
        ctx_reg = pctx.getRegister(ctx_name)
        run_reg = pctx.getRegister(run_name)
        if ctx_reg is None:
            print("  ! context register %s not defined; skipping pair" % ctx_name)
            continue
        if run_reg is None:
            print("  ! runtime register %s not defined; skipping pair" % run_name)
            continue
        pairs.append((ctx_reg, run_reg, ctx_name, run_name))

    if not pairs:
        print("No register pairs available; check slaspec context definitions.")
        return

    funcs = list(prog.getFunctionManager().getFunctions(True))
    print("Syncing %d page-register pairs across %d functions..." % (len(pairs), len(funcs)))

    n_funcs_touched = 0
    n_writes = 0
    for func in funcs:
        entry = func.getEntryPoint()
        wrote_here = False
        for ctx_reg, run_reg, ctx_name, run_name in pairs:
            rv = pctx.getRegisterValue(ctx_reg, entry)
            if rv is None or not rv.hasValue():
                continue
            val = rv.getUnsignedValue()  # BigInteger or None
            if val is None:
                continue
            # Skip if the runtime register already carries this value at entry.
            existing = pctx.getRegisterValue(run_reg, entry)
            if existing is not None and existing.hasValue() \
               and existing.getUnsignedValue() == val:
                continue
            new_rv = RegisterValue(run_reg, val)
            try:
                pctx.setRegisterValue(entry, entry, new_rv)
                n_writes += 1
                wrote_here = True
            except Exception as e:
                print("  ! could not set %s=0x%X at %s: %s" %
                      (run_name, val.longValue(), entry, e))
        if wrote_here:
            n_funcs_touched += 1

    print("Updated %d runtime register values across %d functions." %
          (n_writes, n_funcs_touched))
    print("")
    print("Next: Analysis -> One Shot -> Constant Reference Analyzer")
    print("      (and any other propagation passes you usually run).")

main()
