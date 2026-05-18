# Full post-import pipeline for the SC-55 mkII firmware in Ghidra.
#
# Run this once after importing either ROM into a fresh project as raw binary
# with language "Hitachi:big:H8/520:default". The script orchestrates:
#
#   1. load_sc55mkii.py         -- build the SC-55 mkII memory map, load ROMs,
#                                  label peripheral registers.
#   2. Auto-analysis pass #1    -- decode from the reset vector, identify
#                                  functions, propagate registers, etc.
#   3. clean_unused_vectors.py  -- retype 0xFFFFFFFF vector slots as dwords
#                                  so they stop throwing address-out-of-bounds.
#   4. sync_page_registers.py   -- copy *_ctx context values onto matching
#                                  runtime registers at each function entry.
#   5. Auto-analysis pass #2    -- let constant propagation pick up the
#                                  newly-seeded runtime register values.
#   6. prune_stale_symbols.py   -- drop orphaned auto-generated functions
#                                  and labels (zero inbound refs).
#   7. strip_stack_push_refs.py -- remove the secondary WRITE references
#                                  that JSR/PJSR/PJMP stack pushes leave behind.
#
# After it finishes, the project should be in a clean analysed state. Open
# the reset vector at 0x0000 and start walking the firmware from there.
#
#@author Giammarco Zacheo & Claude
#@category SC55mkII
#@menupath SC55mkII.Pipeline (full post-import)
#@runtime Jython

from ghidra.app.plugin.core.analysis import AutoAnalysisManager
from ghidra.util.task import TaskMonitor

if monitor is None:
    monitor = TaskMonitor.DUMMY

def heading(text):
    print("")
    print("=" * 64)
    print("  " + text)
    print("=" * 64)

def run(script_name):
    heading("Running %s" % script_name)
    try:
        runScript(script_name)
    except Exception as e:
        print("  ! %s failed: %s" % (script_name, e))
        print("  ! continuing pipeline anyway")

def auto_analyze(label):
    heading("Auto-Analysis: %s" % label)
    # analyze() is a GhidraScript builtin; runs the full analyzer chain
    # synchronously and returns when complete.
    analyze(currentProgram)
    # Defensive: in case anything is still in flight, block until idle.
    aam = AutoAnalysisManager.getAnalysisManager(currentProgram)
    aam.waitForAnalysis(None, monitor)
    print("Analysis complete.")

def main():
    heading("SC-55 mkII post-import pipeline")
    print("Working program: %s" % currentProgram.getName())
    print("Language       : %s" % currentProgram.getLanguageID())

    # Phase 1: memory map + ROM load
    run("load_sc55mkii.py")

    # Phase 2: first analysis pass -- discovers functions, runs constant prop,
    #          propagates context fields, creates the bulk of references.
    auto_analyze("pass #1 (after memory map)")

    # Phase 3: structural cleanup that depends on the analysis pass
    run("clean_unused_vectors.py")
    run("sync_page_registers.py")
    run("apply_sc55mkii_control_rom_layout.py")

    # Phase 4: second analysis pass -- now that runtime CP/DP/EP/TP/BR have
    #          been seeded at function entries from the context fields, the
    #          constant propagator can resolve more cross-page references.
    auto_analyze("pass #2 (after register sync)")

    # Phase 5: post-analysis cleanup that removes residue
    run("prune_stale_symbols.py")
    run("strip_stack_push_refs.py")

    heading("Pipeline complete")
    print("Suggested next step: navigate to reset_vector at 0x0000 and follow")
    print("the boot path through ROM1 into ROM2 (firmware entry at 0x040000).")

main()
