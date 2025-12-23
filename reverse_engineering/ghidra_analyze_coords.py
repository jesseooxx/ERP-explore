
# Ghidra Python Script - Analyze nrp32.exe coordinate system
# Run with: analyzeHeadless <project_location> <project_name> -import nrp32.exe -postScript analyze_coords.py

from ghidra.program.model.symbol import *
from ghidra.program.model.listing import *
from ghidra.app.decompiler import *

# Get current program
program = getCurrentProgram()
listing = program.getListing()

print("="*70)
print("Ghidra Auto-Analysis: nrp32.exe Coordinate System")
print("="*70)

# Find all calls to SetMapMode
fm = program.getFunctionManager()
for func in fm.getFunctions(True):
    func_name = func.getName()

    if 'SetMapMode' in func_name or 'TextOut' in func_name:
        print(f"\nFunction: {func_name} @ {func.getEntryPoint()}")

        # Get all call sites
        refs = func.getSymbol().getReferences()
        for ref in refs:
            if ref.getReferenceType().isCall():
                call_addr = ref.getFromAddress()
                print(f"  Called from: {call_addr}")

                # Get instructions before call
                insn_addr = call_addr.subtract(20)
                for i in range(10):
                    insn = listing.getInstructionAt(insn_addr)
                    if insn:
                        print(f"    {insn.getAddressString(False, False)}: {insn}")
                        insn_addr = insn.getNext().getAddress()

# Export findings
print("\n" + "="*70)
print("Key Findings Export")
print("="*70)
print("Analysis complete. Check Ghidra GUI for detailed decompilation.")
