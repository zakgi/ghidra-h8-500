# Remove stack-push WRITE references that get attached as secondary OP-0
# references on JSR/PJSR/PJMP instructions.
#
# Background: the slaspec models these instructions' stack pushes as direct
# *:2 SP24 = value writes. Ghidra's analyzer tracks SP24, figures out the
# absolute stack addresses being written, and creates secondary WRITE
# references from the source instruction to those addresses. They're not
# wrong, just noisy -- those addresses really are being written, but as
# return-address pushes, not as data references to track.
#
# Heuristic: if an instruction's PRIMARY OP-0 reference is a control-flow
# type (UNCONDITIONAL_CALL, COMPUTED_CALL, UNCONDITIONAL_JUMP, etc.), any
# SECONDARY OP-0 WRITE references on it are stack-push side effects and
# can be safely deleted. This protects legitimate data writes (where the
# primary OP-0 is itself a WRITE/READ).
#
# Idempotent: re-running after analysis just trims any new ones.
#
#@author Giammarco Zacheo & Claude
#@category SC55mkII
#@menupath SC55mkII.Strip stack-push refs
#@runtime Jython

from ghidra.program.model.symbol import RefType
from ghidra.util.task import TaskMonitor

# When invoked via runScript() the injected `monitor` global is None.
if monitor is None:
    monitor = TaskMonitor.DUMMY

FLOW_TYPES = {
    "UNCONDITIONAL_CALL",
    "COMPUTED_CALL",
    "CONDITIONAL_CALL",
    "UNCONDITIONAL_JUMP",
    "COMPUTED_JUMP",
    "CONDITIONAL_JUMP",
    "CALL_TERMINATOR",
    "JUMP_TERMINATOR",
    "FALL_THROUGH",
}

def main():
    prog = currentProgram
    rm = prog.getReferenceManager()
    listing = prog.getListing()

    n_removed = 0
    n_instr_checked = 0

    instr_iter = listing.getInstructions(True)
    while instr_iter.hasNext():
        if monitor.isCancelled():
            break
        instr = instr_iter.next()
        n_instr_checked += 1

        refs = list(instr.getReferencesFrom())
        if not refs:
            continue

        # Find the primary OP-0 reference; only proceed if it's control-flow.
        primary_is_flow = False
        for r in refs:
            if r.isPrimary() and r.getOperandIndex() == 0:
                tn = r.getReferenceType().getName()
                if tn in FLOW_TYPES:
                    primary_is_flow = True
                break  # only one primary per operand position

        if not primary_is_flow:
            continue

        # Drop the secondary OP-0 WRITE refs that are stack-push side effects.
        for r in refs:
            if r.isPrimary():
                continue
            if r.getOperandIndex() != 0:
                continue
            if r.getReferenceType() != RefType.WRITE:
                continue
            rm.delete(r)
            n_removed += 1

    print("Checked %d instructions, removed %d stack-push WRITE refs." %
          (n_instr_checked, n_removed))

main()
